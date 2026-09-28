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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Holds a token request to the key or certificate its grant was bound to: the dpop_jkt committed at the
/// authorization request (RFC 9449 section 10) and the certificate a certificate-bound grant was issued to
/// (RFC 8705 section 4).
/// </summary>
/// <remarks>
/// Runs AFTER <see cref="AuthorizationGrantValidator"/>, since every check here reads the grant it resolves,
/// and after <see cref="DPoPTokenEndpointValidator"/>, whose validated proof key it compares. The grants spent
/// while they are resolved - a device code, a backchannel authentication request - are not bound to a key or
/// a certificate by this library, so nothing here refuses one of them after it is gone unless a host bound it
/// itself. For a grant that is bound, a refusal says the request is not the one the grant was bound to.
/// </remarks>
public partial class DPoPBindingValidator(ILogger<DPoPBindingValidator> logger) : ITokenContextValidator
{
    /// <inheritdoc/>
    public Task<OidcError?> ValidateAsync(TokenValidationContext context, CancellationToken cancellationToken)
    {
        if (ValidateCertificateBinding(context) is { } certificateError)
            return Task.FromResult<OidcError?>(certificateError);

        var committed = context.AuthorizedGrant.Context.ProofKeyThumbprint;

        return Task.FromResult(context.ProofKeyThumbprint is { } presented
            ? ValidatePresentedKey(committed, presented)
            : ValidateMissingProof(committed));
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
    /// RFC 9449 section 10: a request that carried no DPoP proof is refused when the authorization request
    /// committed a dpop_jkt.
    /// </summary>
    private OidcError? ValidateMissingProof(string? committed)
    {
        if (committed is null)
            return null;

        // The authorization request committed to a proof-of-possession key via the dpop_jkt parameter, so
        // presenting the auth code without the proof is the very attack the carry-over closes.
        LogProofRequiredButMissing("section 10 dpop_jkt carry-over");
        return new OidcError(
            ErrorCodes.InvalidDPoPProof,
            "Authorization request committed to a DPoP key but no proof was presented.");
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
}
