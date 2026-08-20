// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using UserInfoRequest = Abblix.Oidc.Server.Model.UserInfoRequest;

namespace Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

/// <summary>Formats the result of an OpenID Connect UserInfo request into an <see cref="IResult"/>.</summary>
public interface IUserInfoResponseFormatter
{
    /// <summary>Formats the UserInfo result (plain JSON, or a signed JWT when the client registered a
    /// <c>userinfo_signed_response_alg</c>, on success; the OAuth error otherwise).</summary>
    Task<IResult> FormatResponseAsync(UserInfoRequest request, Result<UserInfoFoundResponse, OidcError> response);
}
