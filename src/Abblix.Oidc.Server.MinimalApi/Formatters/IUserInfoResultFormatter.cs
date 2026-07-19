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
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using UserInfoRequest = Abblix.Oidc.Server.Model.UserInfoRequest;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>Formats the result of an OpenID Connect UserInfo request into an <see cref="IResult"/>.</summary>
public interface IUserInfoResultFormatter
{
    /// <summary>Formats the UserInfo result (plain JSON, or a signed JWT when the client registered a
    /// <c>userinfo_signed_response_alg</c>, on success; the OAuth error otherwise).</summary>
    Task<IResult> FormatResponseAsync(UserInfoRequest request, Result<UserInfoFoundResponse, OidcError> response);
}
