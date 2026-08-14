// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Buffers.Text;
using System.Security.Cryptography;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.Nonces;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Token-endpoint enforcement of RFC 9449 DPoP: validates the proof JWT carried on the
/// inbound <c>DPoP</c> header against the request's method+URI, runs the layered
/// nonce-policy if the deployment requires it, and stashes the proof's JWK thumbprint on
/// the validation context so the processor can bind <c>cnf.jkt</c> onto the issued access
/// token.
/// </summary>
/// <remarks>
/// Sits AFTER <see cref="ClientValidator"/> in the composite - that ordering is
/// load-bearing because this step reads <see cref="TokenValidationContext.ClientInfo"/>
/// to decide whether DPoP is mandatory (<see cref="ClientInfo.RequireDPoP"/>)
/// or opportunistic. When the client opts in but the proof is missing, the request is
/// rejected with <c>invalid_dpop_proof</c>; when the client does not opt in, a missing
/// proof is silently accepted (Bearer token issued downstream) and a present-and-valid
/// proof still binds the token (RFC 9449 §5.2 server-side opportunistic binding).
/// </remarks>
public partial class DPoPTokenEndpointValidator(
    ILogger<DPoPTokenEndpointValidator> logger,
    IProofValidator proofValidator,
    INonceService nonceService,
    IOptionsMonitor<OidcOptions> options) : DPoPNonceValidator(nonceService), ITokenContextValidator
{
    /// <inheritdoc/>
    public async Task<OidcError?> ValidateAsync(TokenValidationContext context, CancellationToken cancellationToken)
    {
        if (ValidateCertificateBinding(context) is { } certificateError)
            return certificateError;

        var committed = context.AuthorizedGrant.Context.ProofKeyThumbprint;

        return context.ClientRequest is { DPoPProof: { } proofJwt }
            ? await ValidatePresentedProofAsync(context, proofJwt, committed)
            : ValidateMissingProof(context, committed);
    }

    /// <summary>
    /// RFC 8705 §4: a grant issued with a certificate-bound token must be redeemed (e.g. on refresh) by
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
    /// Decides whether a request that carried no DPoP proof is acceptable: rejected when the client
    /// mandates DPoP (RFC 9449 §5.2), when a sender-constraining security profile is unmet, or when the
    /// authorization request committed a dpop_jkt (RFC 9449 §10); otherwise a Bearer token is allowed.
    /// </summary>
    private OidcError? ValidateMissingProof(TokenValidationContext context, string? committed)
    {
        // The per-client dpop_bound_access_tokens flag (RFC 9449 §5.2) mandates DPoP specifically, so
        // an mTLS-bound token does not satisfy it and a missing proof is rejected outright.
        if (context.ClientInfo.RequireDPoP)
        {
            LogProofRequiredButMissing("client policy");
            return new OidcError(
                ErrorCodes.InvalidDPoPProof,
                "DPoP proof is required for this client.");
        }

        // A high-assurance profile (FAPI 2.0) requires a sender-constrained token, satisfied by either a
        // DPoP proof or a certificate-bound token over mutual TLS (RFC 8705 §3). With the proof absent, the
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
            // RFC 9449 §10: the authorization request committed to a proof-of-possession key via the dpop_jkt
            // parameter, so presenting the auth code without the proof is the very attack the carry-over closes.
            LogProofRequiredButMissing("§10 dpop_jkt carry-over");
            return new OidcError(
                ErrorCodes.InvalidDPoPProof,
                "Authorization request committed to a DPoP key but no proof was presented.");
        }

        return null;
    }

    /// <summary>
    /// Validates a presented DPoP proof (RFC 9449): signature/binding via <see cref="IProofValidator"/>,
    /// the committed dpop_jkt match, and the nonce policy, then stashes the proof-key thumbprint so the
    /// processor can bind cnf.jkt onto the issued token.
    /// </summary>
    private async Task<OidcError?> ValidatePresentedProofAsync(
        TokenValidationContext context, string proofJwt, string? committed)
    {
        var proofResult = await proofValidator.ValidateAsync(proofJwt);

        if (proofResult.TryGetFailure(out var proofError))
        {
            LogProofRejected(proofError.Reason);
            return new OidcError(
                ErrorCodes.InvalidDPoPProof,
                $"DPoP proof rejected ({proofError.Reason}).");
        }

        var proof = proofResult.GetSuccess();

        if (committed is not null && committed != proof.ProofKeyThumbprint)
        {
            LogProofKeyMismatch(committed, proof.ProofKeyThumbprint);
            return new OidcError(
                ErrorCodes.InvalidDPoPProof,
                "DPoP proof key does not match the dpop_jkt committed at the authorization request.");
        }

        if (options.CurrentValue.DPoP.Nonce.RequireAtTokenEndpoint)
        {
            var nonceError = await EnforceNonceAsync(proof);
            if (nonceError is not null)
                return nonceError;
        }

        context.ProofKeyThumbprint = proof.ProofKeyThumbprint;
        return null;
    }

    /// <summary>
    /// Whether the client authenticates with mutual TLS (<c>tls_client_auth</c> /
    /// <c>self_signed_tls_client_auth</c>). Such a client has already proved possession of its
    /// certificate as part of authentication, so the RFC 8705 §4 certificate-binding check on a
    /// certificate-bound grant is redundant for it and is skipped.
    /// </summary>
    private static bool AuthenticatesByMutualTls(ClientInfo clientInfo)
        => clientInfo.TokenEndpointAuthMethod
            is ClientAuthenticationMethods.TlsClientAuth
            or ClientAuthenticationMethods.SelfSignedTlsClientAuth;

    /// <summary>
    /// Whether the access token about to be issued will be certificate-bound (RFC 8705 §3), and
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
