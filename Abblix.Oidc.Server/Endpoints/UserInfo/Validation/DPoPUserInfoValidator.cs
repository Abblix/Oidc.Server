// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.Nonces;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.UserInfo.Validation;

/// <summary>
/// Resource-server-side enforcement of RFC 9449 DPoP at the UserInfo endpoint. Mirrors the
/// shape of <see cref="Endpoints.Token.Validation.DPoPTokenEndpointValidator"/> so the
/// branching logic stays symmetric across endpoints; differences are limited to the
/// trigger (<c>cnf.jkt</c> on the inbound access token) and the error envelope (typed
/// <see cref="InvalidDPoPProofError"/> / <see cref="UseDPoPNonceError"/> so the response
/// formatter can emit the §7.1 <c>WWW-Authenticate: DPoP</c> challenge).
/// </summary>
public partial class DPoPUserInfoValidator(
    ILogger<DPoPUserInfoValidator> logger,
    IProofValidator proofValidator,
    INonceService nonceService,
    IOptionsMonitor<OidcOptions> options) : DPoPNonceValidator(nonceService), IDPoPUserInfoValidator
{
    /// <inheritdoc/>
    public async Task<OidcError?> ValidateAsync(
        ClientRequest clientRequest,
        JsonWebToken accessToken,
        string rawAccessToken)
    {
        var committed = accessToken.Payload.Confirmation?.JwkThumbprint;
        var scheme = clientRequest.AuthorizationHeader?.Scheme;
        var proofJwt = clientRequest.DPoPProof;

        if (committed is null)
        {
            // Unbound (Bearer) access token. Reject the DPoP scheme to keep presentation
            // modes unambiguous: a token without cnf.jkt was issued for the Bearer scheme
            // (RFC 9449 §7.1) and presenting it via DPoP would bypass logging/policy
            // gates that key off scheme.
            if (scheme == TokenTypes.DPoP)
            {
                return new OidcError(
                    ErrorCodes.InvalidToken,
                    "Access token is not DPoP-bound; use the Bearer scheme.");
            }

            return null;
        }

        if (scheme != TokenTypes.DPoP)
        {
            return new OidcError(
                ErrorCodes.InvalidToken,
                "DPoP-bound access token must be presented via the DPoP scheme.");
        }

        if (proofJwt is null)
            return new InvalidDPoPProofError("DPoP proof is required for the DPoP-bound access token.");

        var proofResult = await proofValidator.ValidateAsync(proofJwt, rawAccessToken);
        if (proofResult.TryGetFailure(out var proofError))
            return new InvalidDPoPProofError($"DPoP proof rejected ({proofError.Reason}).");

        var proof = proofResult.GetSuccess();
        if (proof.ProofKeyThumbprint != committed)
        {
            return new InvalidDPoPProofError(
                "DPoP proof key does not match the cnf.jkt of the access token.");
        }

        if (options.CurrentValue.DPoP.Nonce.RequireAtUserInfoEndpoint)
        {
            var nonceError = await EnforceNonceAsync(proof);
            if (nonceError is not null)
                return nonceError;
        }

        return null;
    }
}
