// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
/// formatter can emit the section 7.1 <c>WWW-Authenticate: DPoP</c> challenge).
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
        var schemeDPoP = clientRequest is { AuthorizationHeader.Scheme: TokenTypes.DPoP };

        if (accessToken is not { Payload.Confirmation.JwkThumbprint: {} committed})
        {
            // Unbound (Bearer) access token. Reject the DPoP scheme to keep presentation
            // modes unambiguous: a token without cnf.jkt was issued for the Bearer scheme
            // (RFC 9449 section 7.1) and presenting it via DPoP would bypass logging/policy
            // gates that key off scheme.
            if (schemeDPoP)
            {
                LogSchemeBindingMismatch(TokenTypes.DPoP, tokenIsBound: false);
                return new OidcError(
                    ErrorCodes.InvalidToken,
                    "Access token is not DPoP-bound; use the Bearer scheme.");
            }

            return null;
        }

        if (!schemeDPoP)
        {
            LogSchemeBindingMismatch(clientRequest.AuthorizationHeader?.Scheme ?? "<missing>", tokenIsBound: true);
            return new OidcError(
                ErrorCodes.InvalidToken,
                "DPoP-bound access token must be presented via the DPoP scheme.");
        }

        if (clientRequest is not { DPoPProof: {} proofJwt})
        {
            LogProofRequiredButMissing("DPoP-bound access token");
            return new InvalidDPoPProofError("DPoP proof is required for the DPoP-bound access token.");
        }

        var proofResult = await proofValidator.ValidateAsync(proofJwt, rawAccessToken);
        if (proofResult.TryGetFailure(out var proofError))
        {
            LogProofRejected(proofError.Reason);
            return new InvalidDPoPProofError($"DPoP proof rejected ({proofError.Reason}).");
        }

        var proof = proofResult.GetSuccess();
        if (proof.ProofKeyThumbprint != committed)
        {
            LogProofKeyMismatch(committed, proof.ProofKeyThumbprint);
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
