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
using Abblix.Oidc.Server.Features.Storages;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Builds the <c>code</c> response-type component of an authorization endpoint success
/// response — the Authorization Code Flow contributor. Generates an authorization code via
/// <see cref="IAuthorizationCodeService"/> and stores it on the running
/// <see cref="SuccessfullyAuthenticated"/> result. Registered by default through
/// <c>AddAuthorizationEndpoint()</c>; covers the OAuth 2.1-recommended flow. Declares
/// <c>authorization_code</c> in <see cref="GrantTypesSupported"/> so the discovery
/// endpoint and registration-time gates aggregate it transparently.
/// </summary>
public class AuthorizationCodeBuilder(IAuthorizationCodeService authorizationCodeService)
    : IAuthorizationResponseBuilder
{
    /// <inheritdoc />
    public string ResponseType => ResponseTypes.Code;

    /// <inheritdoc />
    public IEnumerable<string> GrantTypesSupported
    {
        get { yield return GrantTypes.AuthorizationCode; }
    }

    /// <inheritdoc />
    public async Task BuildResponseAsync(
        ValidAuthorizationRequest request,
        AuthorizedGrant authorizedGrant,
        SuccessfullyAuthenticated result)
    {
        result.Code = await authorizationCodeService.GenerateAuthorizationCodeAsync(
            authorizedGrant,
            request.ClientInfo.AuthorizationCodeExpiresIn);
    }
}
