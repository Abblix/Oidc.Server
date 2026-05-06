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
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Endpoints.Authorization.ResponseProcessors;

/// <summary>
/// Processor for the <c>code</c> response type — the Authorization Code Flow component. Generates
/// an authorization code via <see cref="IAuthorizationCodeService"/> and stores it on the
/// running <see cref="SuccessfullyAuthenticated"/> result. Registered by default; this processor
/// covers the OAuth 2.1-recommended flow.
/// </summary>
public class AuthorizationCodeProcessor(IAuthorizationCodeService authorizationCodeService)
    : IAuthorizationResponseProcessor
{
    /// <inheritdoc />
    public string ResponseType => ResponseTypes.Code;

    /// <inheritdoc />
    public async Task ProcessAsync(
        ValidAuthorizationRequest request,
        AuthorizedGrant authorizedGrant,
        SuccessfullyAuthenticated result)
    {
        result.Code = await authorizationCodeService.GenerateAuthorizationCodeAsync(
            authorizedGrant,
            request.ClientInfo.AuthorizationCodeExpiresIn);
    }
}
