// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Tokens;

namespace Abblix.Oidc.Server.Features.ImplicitFlow;

/// <summary>
/// Builds the <c>token</c> response-type component of an authorization endpoint success
/// response - the access-token contributor of the Implicit / Hybrid Flow. Generates an
/// access token via <see cref="IAccessTokenService"/> and stores it on the running
/// <see cref="SuccessfullyAuthenticated"/> result. Registered ONLY when a host calls
/// <c>EnableImplicitFlow()</c>; absent by default per OAuth 2.1 (draft) deprecation guidance.
/// Declares <c>implicit</c> in <see cref="GrantTypesSupported"/> so opting in surfaces the
/// implicit grant in discovery and registration-time gating without extra DI wiring.
/// </summary>
public class TokenResponseBuilder(IAccessTokenService accessTokenService)
    : IAuthorizationResponseBuilder
{
    /// <inheritdoc />
    public string ResponseType => ResponseTypes.Token;

    /// <inheritdoc />
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.Implicit; }
    }

    /// <inheritdoc />
    public async Task BuildResponseAsync(
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
