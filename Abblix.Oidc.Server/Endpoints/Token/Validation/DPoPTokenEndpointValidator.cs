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
/// Sits AFTER <see cref="ClientValidator"/> in the composite — that ordering is
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
    public async Task<OidcError?> ValidateAsync(TokenValidationContext context)
    {
        var proofJwt = context.ClientRequest.DPoPProof;
        var committed = context.AuthorizedGrant?.Context.ProofKeyThumbprint;

        if (proofJwt is null)
        {
            if (context.ClientInfo.RequireDPoP)
            {
                return new OidcError(
                    ErrorCodes.InvalidDPoPProof,
                    "DPoP proof is required for this client.");
            }

            if (committed is not null)
            {
                // RFC 9449 §10: the authorization request committed to a proof-of-possession
                // key via dpop_jkt; presenting the auth code without the proof is the very
                // attack the carry-over closes.
                return new OidcError(
                    ErrorCodes.InvalidDPoPProof,
                    "Authorization request committed to a DPoP key but no proof was presented.");
            }

            return null;
        }

        var proofResult = await proofValidator.ValidateAsync(proofJwt);

        if (proofResult.TryGetFailure(out var proofError))
        {
            return new OidcError(
                ErrorCodes.InvalidDPoPProof,
                $"DPoP proof rejected ({proofError.Reason}).");
        }

        var proof = proofResult.GetSuccess();

        if (committed is not null && committed != proof.ProofKeyThumbprint)
        {
            return new OidcError(
                ErrorCodes.InvalidDPoPProof,
                "DPoP proof key does not match the dpop_jkt committed at the authorization request.");
        }

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
}
