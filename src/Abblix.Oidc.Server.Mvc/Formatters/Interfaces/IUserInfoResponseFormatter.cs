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
using Microsoft.AspNetCore.Mvc;
using UserInfoRequest = Abblix.Oidc.Server.Model.UserInfoRequest;

namespace Abblix.Oidc.Server.Mvc.Formatters.Interfaces;

/// <summary>
/// Defines an interface for formatting an OpenID Connect UserInfo response as a low-level response object to return to the client.
/// </summary>
public interface IUserInfoResponseFormatter
{
    /// <summary>
    /// Formats an OpenID Connect UserInfo response asynchronously as a low-level response object to return to the client.
    /// </summary>
    /// <param name="request">The UserInfo request.</param>
    /// <param name="response">The UserInfo response to be formatted.</param>
    /// <returns>A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult"/>.</returns>
    Task<ActionResult> FormatResponseAsync(UserInfoRequest request, Result<UserInfoFoundResponse, OidcError> response);
}
