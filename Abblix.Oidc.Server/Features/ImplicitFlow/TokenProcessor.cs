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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Tokens;

namespace Abblix.Oidc.Server.Features.ImplicitFlow;

/// <summary>
/// Processor for the <c>token</c> response type — the access-token component of the Implicit /
/// Hybrid Flow. Generates an access token via <see cref="IAccessTokenService"/> and stores it
/// on the running <see cref="SuccessfullyAuthenticated"/> result. Registered ONLY when a host
/// calls <c>EnableImplicitFlow()</c>; absent by default per OAuth 2.1 §1.4 deprecation guidance.
/// </summary>
public class TokenProcessor(IAccessTokenService accessTokenService)
    : IAuthorizationResponseProcessor
{
    /// <inheritdoc />
    public string ResponseType => ResponseTypes.Token;

    /// <inheritdoc />
    public async Task ProcessAsync(
        ValidAuthorizationRequest request,
        AuthorizedGrant authorizedGrant,
        SuccessfullyAuthenticated result)
    {
        result.TokenType = TokenTypes.Bearer;

        result.AccessToken = await accessTokenService.CreateAccessTokenAsync(
            authorizedGrant.AuthSession,
            authorizedGrant.Context,
            request.ClientInfo);
    }
}
