// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Security.Cryptography;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Holds a token request to the key or certificate its grant was bound to: the dpop_jkt committed at the
/// authorization request (RFC 9449 section 10), the certificate a certificate-bound grant was issued to
/// (RFC 8705 section 4), and the sender-constrained token a security profile demands.
/// </summary>
/// <remarks>
/// Runs AFTER <see cref="AuthorizationGrantValidator"/>, since every check here reads the grant it resolves,
/// and after <see cref="DPoPTokenEndpointValidator"/>, whose validated proof key it compares. A refusal here
/// can therefore come after a device code or a backchannel authentication request has been spent, and is
/// meant to: it says the request is not the one the grant was bound to, which no retry of it cures.
/// </remarks>
public partial class DPoPBindingValidator(
    ILogger<DPoPBindingValidator> logger,
    IOptionsMonitor<OidcOptions> options) : ITokenContextValidator
{
    /// <inheritdoc/>
    public Task<OidcError?> ValidateAsync(TokenValidationContext context, CancellationToken cancellationToken)
    {
        if (ValidateCertificateBinding(context) is { } certificateError)
            return Task.FromResult<OidcError?>(certificateError);

        var committed = context.AuthorizedGrant.Context.ProofKeyThumbprint;

        return Task.FromResult(context.ProofKeyThumbprint is { } presented
            ? ValidatePresentedKey(committed, presented)
            : ValidateMissingProof(context, committed));
    }

    /// <summary>
    /// RFC 8705 section 4: a grant issued with a certificate-bound token must be redeemed (e.g. on refresh) by
    /// re-presenting the same certificate. Clients that authenticate via mutual TLS are skipped - their
    /// authentication already proved certificate possession on this connection. For every other
    /// authentication method (including public 'none') the binding is otherwise never checked, so a stolen
    /// certificate-bound refresh token would be redeemable with no certificate at all while the issued
    /// token stayed bound to the original thumbprint.
    /// </summary>
    private static OidcError? ValidateCertificateBinding(TokenValidationContext context)
    {
        var committedCertThumbprint = context.AuthorizedGrant.Context.CertificateSha256Thumbprint;
        if (committedCertThumbprint is null || AuthenticatesByMutualTls(context.ClientInfo))
            return null;

        var presentedCertThumbprint = context is { ClientRequest.ClientCertificate: { } certificate }
            ? Base64Url.EncodeToString(SHA256.HashData(certificate.RawData))
            : null;

        return string.Equals(presentedCertThumbprint, committedCertThumbprint, StringComparison.Ordinal)
            ? null
            : new OidcError(
                ErrorCodes.InvalidGrant,
                "The grant is bound to a client certificate that was not presented on this request.");
    }

    /// <summary>
    /// RFC 9449 section 10: a proof whose key is not the one the authorization request committed to via
    /// dpop_jkt is refused.
    /// </summary>
    private OidcError? ValidatePresentedKey(string? committed, string presented)
    {
        if (committed is null || committed == presented)
            return null;

        LogProofKeyMismatch(committed, presented);
        return new OidcError(
            ErrorCodes.InvalidDPoPProof,
            "DPoP proof key does not match the dpop_jkt committed at the authorization request.");
    }

    /// <summary>
    /// Decides whether a request that carried no DPoP proof is acceptable for this grant: rejected when a
    /// sender-constraining security profile is unmet, or when the authorization request committed a dpop_jkt
    /// (RFC 9449 section 10); otherwise a Bearer token is allowed.
    /// </summary>
    private OidcError? ValidateMissingProof(TokenValidationContext context, string? committed)
    {
        // A high-assurance profile (FAPI 2.0) requires a sender-constrained token, satisfied by either a
        // DPoP proof or a certificate-bound token over mutual TLS (RFC 8705 section 3). With the proof absent, the
        // requirement is met only when the token will be certificate-bound. In any other case neither
        // mechanism applies and the profile is not satisfied. The profile tightens, and the granular
        // RequireDPoP toggle cannot weaken it.
        if (SecurityProfileRequirements
                .For(context.ClientInfo, options.CurrentValue.DefaultSecurityProfile)
                .RequireSenderConstrainedTokens &&
            !WillIssueCertificateBoundToken(context))
        {
            LogProofRequiredButMissing("security profile");
            return new OidcError(
                ErrorCodes.InvalidDPoPProof,
                "The security profile requires a sender-constrained token: " +
                "present a DPoP proof or authenticate with mutual TLS.");
        }

        if (committed is not null)
        {
            // RFC 9449 section 10: the authorization request committed to a proof-of-possession key via the dpop_jkt
            // parameter, so presenting the auth code without the proof is the very attack the carry-over closes.
            LogProofRequiredButMissing("section 10 dpop_jkt carry-over");
            return new OidcError(
                ErrorCodes.InvalidDPoPProof,
                "Authorization request committed to a DPoP key but no proof was presented.");
        }

        return null;
    }

    /// <summary>
    /// Whether the client authenticates with mutual TLS (<c>tls_client_auth</c> /
    /// <c>self_signed_tls_client_auth</c>). Such a client has already proved possession of its
    /// certificate as part of authentication, so the RFC 8705 section 4 certificate-binding check on a
    /// certificate-bound grant is redundant for it and is skipped.
    /// </summary>
    private static bool AuthenticatesByMutualTls(ClientInfo clientInfo)
        => clientInfo.TokenEndpointAuthMethod
            is ClientAuthenticationMethods.TlsClientAuth
            or ClientAuthenticationMethods.SelfSignedTlsClientAuth;

    /// <summary>
    /// Whether the access token about to be issued will be certificate-bound (RFC 8705 section 3), and
    /// therefore sender-constrained via mutual TLS rather than DPoP. Mirrors the binding decision in
    /// TokenAuthorizationContextEvaluator: a binding the grant already carries (e.g. on refresh), or a
    /// certificate presented by a client that authenticates with mTLS or has opted into
    /// certificate-bound tokens. Used to credit the mTLS mechanism when a security profile requires a
    /// sender-constrained token but the client presents no DPoP proof.
    /// </summary>
    private static bool WillIssueCertificateBoundToken(TokenValidationContext context)
    {
        return context switch
        {
            { AuthorizedGrant.Context.CertificateSha256Thumbprint: not null } => true,
            { ClientRequest.ClientCertificate: null } => false,
            _ => AuthenticatesByMutualTls(context.ClientInfo) ||
                 context.ClientInfo.TlsClientCertificateBoundAccessTokens,
        };
    }
}
