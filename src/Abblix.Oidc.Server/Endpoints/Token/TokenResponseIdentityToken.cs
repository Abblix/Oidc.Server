// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Tokens;

namespace Abblix.Oidc.Server.Endpoints.Token;

/// <summary>
/// What the ID token of a token response is issued from (OpenID Connect Core 1.0 section 3.1.3.3).
/// </summary>
internal static class TokenResponseIdentityToken
{
    /// <summary>
    /// The request for the ID token answering <paramref name="request"/>, issued beside
    /// <paramref name="accessToken"/> and, where one was minted, <paramref name="refreshToken"/>.
    /// </summary>
    /// <param name="request">The validated token request.</param>
    /// <param name="authContext">What the response is granted.</param>
    /// <param name="accessToken">The access token of the response, which the ID token binds with at_hash.</param>
    /// <param name="refreshToken">The refresh token of the response, or null where none is issued.</param>
    public static IdentityTokenRequest For(
        ValidTokenRequest request,
        AuthorizationContext authContext,
        string accessToken,
        string? refreshToken)
    {
        // The bindings exist only when the caller says it IS the push path. The mode could be read
        // off clientInfo instead, and is not, so that this method does not have to know CIBA's
        // delivery rules to serve every other grant type - see PushDeliveryBindings.
        //
        // The refresh token is read from the RESPONSE because it was minted in the step before. That order
        // is load-bearing: assembling these bindings before the step that mints it silently drops
        // rt_hash from every push notification that carries one.
        var pushBindings = request.PushDeliveryOf is { } authenticationRequestId
            ? new PushDeliveryBindings(authenticationRequestId, refreshToken)
            : null;

        return new IdentityTokenRequest(
            request.AuthorizedGrant.AuthSession,
            authContext,
            request.ClientInfo,
            IncludeUserClaims: false,
            AuthorizationCode: null,
            accessToken,
            // FAPI 1.0 Part 2 section 5.2.2.1 lets s_hash be omitted here once the authorization response
            // carried it, and the token request holds no state to hash anyway.
            State: null,
            pushBindings);
    }
}
