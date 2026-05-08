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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.Nonces;
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
/// Sits AFTER <see cref="ClientValidator"/> in the composite — that ordering is
/// load-bearing because this step reads <see cref="TokenValidationContext.ClientInfo"/>
/// to decide whether DPoP is mandatory (<see cref="ClientInfo.RequireDPoP"/>)
/// or opportunistic. When the client opts in but the proof is missing, the request is
/// rejected with <c>invalid_dpop_proof</c>; when the client does not opt in, a missing
/// proof is silently accepted (Bearer token issued downstream) and a present-and-valid
/// proof still binds the token (RFC 9449 §5.2 server-side opportunistic binding).
/// </remarks>
public class DPoPTokenEndpointValidator(
    IProofValidator proofValidator,
    INonceService nonceService,
    IRequestInfoProvider requestInfoProvider,
    IOptionsMonitor<OidcOptions> options) : ITokenContextValidator
{
    /// <inheritdoc/>
    public async Task<OidcError?> ValidateAsync(TokenValidationContext context)
    {
        var proofJwt = context.ClientRequest.DPoPProof;
        if (proofJwt is null)
        {
            if (context.ClientInfo.RequireDPoP)
            {
                return new OidcError(
                    ErrorCodes.InvalidDPoPProof,
                    "DPoP proof is required for this client.");
            }

            return null;
        }

        var proofResult = await proofValidator.ValidateAsync(
            proofJwt,
            requestInfoProvider.RequestMethod,
            new Uri(requestInfoProvider.RequestUri));

        if (proofResult.TryGetFailure(out var proofError))
        {
            return new OidcError(
                ErrorCodes.InvalidDPoPProof,
                $"DPoP proof rejected ({proofError.Reason}).");
        }

        var proof = proofResult.GetSuccess();

        var nonceOptions = options.CurrentValue.DPoP.Nonce;
        if (nonceOptions.RequireAtTokenEndpoint)
        {
            var nonceError = await EnforceNonceAsync(proof);
            if (nonceError is not null)
                return nonceError;
        }

        context.ProofKeyThumbprint = proof.ProofKeyThumbprint;
        return null;
    }

    /// <summary>
    /// Enforces the nonce policy at the token endpoint per RFC 9449 §8: the proof MUST
    /// carry a <c>nonce</c> claim accepted by <see cref="INonceService"/>; when missing or
    /// stale, mints a fresh nonce and surfaces it as a
    /// <see cref="DPoPNonceRequiredError"/> so the response formatter can attach the
    /// <c>DPoP-Nonce</c> header to the error response.
    /// </summary>
    private async Task<OidcError?> EnforceNonceAsync(Proof proof)
    {
        var nonceClaim = proof.Token.Payload.Nonce;
        if (nonceClaim is null)
            return await NonceRequired();

        var failure = await nonceService.ValidateAsync(nonceClaim);
        if (failure is not null)
            return await NonceRequired();

        return null;
    }

    /// <summary>
    /// Mints a fresh nonce via <see cref="INonceService"/> and wraps it in a
    /// <see cref="DPoPNonceRequiredError"/>. Shared between the missing-nonce and
    /// stale-nonce branches of <see cref="EnforceNonceAsync"/>: both surface the same
    /// challenge to the client and both need a freshly issued nonce so the response
    /// formatter can attach it on the <c>DPoP-Nonce</c> header.
    /// </summary>
    private async Task<DPoPNonceRequiredError> NonceRequired()
        => new(await nonceService.IssueAsync());
}
