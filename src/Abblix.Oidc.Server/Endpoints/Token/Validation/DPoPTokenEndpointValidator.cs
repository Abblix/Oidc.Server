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
    IOptionsMonitor<OidcOptions> options) : DPoPNonceValidator(nonceService), ITokenContextValidator
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
}
