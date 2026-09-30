// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.Issuer;
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
/// proof is accepted (Bearer token issued downstream) unless a security profile demands a
/// sender-constrained token and none will be certificate-bound, and a present-and-valid
/// proof still binds the token (RFC 9449 section 5.2 server-side opportunistic binding).
/// <para>
/// And BEFORE <see cref="AuthorizationGrantValidator"/>, because resolving a device code or a backchannel
/// authentication request spends it. Nothing here reads the grant, so a proof that is refused - a nonce the
/// server asks for, which RFC 9449 section 8 answers by retrying - is refused while the grant can still be
/// redeemed by that retry. What does depend on the grant, the key or certificate it was bound to, is
/// <see cref="DPoPBindingValidator"/>'s.
/// </para>
/// </remarks>
public partial class DPoPTokenEndpointValidator(
    ILogger<DPoPTokenEndpointValidator> logger,
    IProofValidator proofValidator,
    INonceService nonceService,
    IOptionsMonitor<OidcOptions> options,
    IIssuerSettings issuerSettings) : DPoPNonceValidator(nonceService), ITokenContextValidator
{
    /// <inheritdoc/>
    public async Task<OidcError?> ValidateAsync(TokenValidationContext context, CancellationToken cancellationToken)
    {
        if (context.ClientRequest is { DPoPProof: { } proofJwt })
            return await ValidatePresentedProofAsync(context, proofJwt);

        // The per-client dpop_bound_access_tokens flag (RFC 9449 section 5.2) mandates DPoP specifically, so
        // an mTLS-bound token does not satisfy it and a missing proof is rejected outright.
        if (context.ClientInfo.RequireDPoP)
        {
            LogProofRequiredButMissing("client policy");
            return new OidcError(
                ErrorCodes.InvalidDPoPProof,
                "DPoP proof is required for this client.");
        }

        // A high-assurance profile (FAPI 2.0) requires a sender-constrained token, satisfied by a DPoP proof or
        // a certificate-bound token over mutual TLS (RFC 8705 section 3). Without a proof the requirement is met
        // only when the token will be certificate-bound, and that is decided by the client's registration and
        // the certificate on this request, never by the grant: a token is bound to a certificate only for a
        // client registered to bind it. So the answer is given here, before a device code or a backchannel
        // authentication request is spent. The profile tightens, and the granular RequireDPoP toggle cannot
        // weaken it.
        if (SecurityProfileRequirements
                .For(context.ClientInfo, issuerSettings.DefaultSecurityProfile)
                .RequireSenderConstrainedTokens &&
            !WillIssueCertificateBoundToken(context))
        {
            LogProofRequiredButMissing("security profile");
            return new OidcError(
                ErrorCodes.InvalidDPoPProof,
                "The security profile requires a sender-constrained token: " +
                "present a DPoP proof or authenticate with mutual TLS.");
        }

        return null;
    }

    /// <summary>
    /// Validates a presented DPoP proof (RFC 9449): signature/binding via <see cref="IProofValidator"/> and
    /// the nonce policy, then stashes the proof-key thumbprint so the processor can bind cnf.jkt onto the
    /// issued token.
    /// </summary>
    private async Task<OidcError?> ValidatePresentedProofAsync(TokenValidationContext context, string proofJwt)
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
    /// Whether the access token about to be issued will be certificate-bound (RFC 8705 section 3), and
    /// therefore sender-constrained via mutual TLS rather than DPoP: a certificate is presented by a client
    /// that authenticates with mTLS or has registered for certificate-bound tokens. The binding decision in
    /// TokenAuthorizationContextEvaluator also keeps a grant already bound to a certificate bound; such a grant
    /// was issued to a client registered as above, so the two part only for a registration changed since, and
    /// then the profile is held to the registration as it stands.
    /// </summary>
    private static bool WillIssueCertificateBoundToken(TokenValidationContext context)
        => context.ClientRequest.ClientCertificate is not null &&
           (context.ClientInfo.TokenEndpointAuthMethod
                is ClientAuthenticationMethods.TlsClientAuth
                or ClientAuthenticationMethods.SelfSignedTlsClientAuth ||
            context.ClientInfo.TlsClientCertificateBoundAccessTokens);
}
