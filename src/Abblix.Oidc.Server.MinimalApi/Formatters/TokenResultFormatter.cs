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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using TokenRequest = Abblix.Oidc.Server.Model.TokenRequest;
using TokenResponse = Abblix.Oidc.Server.Model.TokenResponse;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats token endpoint results as <see cref="IResult"/>: a JSON token response on success, or the RFC-compliant
/// OAuth error (status, JSON envelope, WWW-Authenticate challenge, DPoP-Nonce) on failure.
/// </summary>
/// <param name="issuerProvider">Supplies the issuer used as the realm on client-authentication challenges.</param>
public class TokenResultFormatter(IIssuerProvider issuerProvider) : ITokenResultFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(TokenRequest request, Result<TokenIssued, OidcError> response)
        => Task.FromResult(response.Match(FormatSuccess, FormatError));

    private static IResult FormatSuccess(TokenIssued success)
    {
        var tokenResponse = new TokenResponse
        {
            AccessToken = success.AccessToken.EncodedJwt,
            TokenType = success.TokenType,
            IssuedTokenType = success.IssuedTokenType,
            ExpiresIn = success.ExpiresIn,

            RefreshToken = success.RefreshToken?.EncodedJwt,
            Scope = success.Scope.ToArray(),
            IdToken = success.IdToken?.EncodedJwt,
            AuthorizationDetails = success.AuthorizationDetails,
        };

        return Results.Json(tokenResponse);
    }

    private IResult FormatError(OidcError error)
    {
        // The shared policy owns the status codes: invalid_client -> 401 with a Basic challenge (RFC 6749 §5.2),
        // everything else -> 400 with the JSON envelope.
        var result = error.Format(StatusCodes.Status400BadRequest, issuerProvider.GetIssuer());

        // RFC 9449 §8: a use_dpop_nonce error MUST carry the fresh nonce on a DPoP-Nonce header. §8.2 asks such
        // responses to be uncacheable; the endpoint-level no-cache filter (see MapOidcEndpoints) covers that.
        if (error is UseDPoPNonceError { Nonce: var nonce })
            result = result.WithHeader(HttpRequestHeaders.DPoPNonce, nonce);

        return result;
    }
}
