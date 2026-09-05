// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;

/// <summary>
/// Generates a response containing information about a user account.
/// </summary>
public interface IUserInfoRequestProcessor
{
	/// <summary>
	/// Asynchronously processes a valid user info request and generates a user info response.
	/// </summary>
	/// <param name="request">The valid user info request to process.</param>
	/// <returns>A <see cref="Task"/> representing the asynchronous operation,
	/// which upon completion will yield a <see cref="Result{UserInfoFoundResponse, AuthError}"/>.</returns>
	Task<Result<UserInfoFoundResponse, OidcError>> ProcessAsync(ValidUserInfoRequest request);
}
