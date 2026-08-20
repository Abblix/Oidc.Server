// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;



namespace Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;

/// <summary>
/// Parses and validates an access token provided in a user info request.
/// </summary>
public interface IUserInfoRequestValidator
{
	/// <summary>
	/// Asynchronously validates a user info request and generates a validation result.
	/// </summary>
	/// <param name="userInfoRequest">The user info request to validate.</param>
	/// <param name="clientRequest">Additional client request information for contextual validation.</param>
	/// <returns>A <see cref="Task"/> representing the asynchronous operation,
	/// which upon completion will yield a <see cref="Result{ValidUserInfoRequest, AuthError}"/>.</returns>
	Task<Result<ValidUserInfoRequest, OidcError>> ValidateAsync(UserInfoRequest userInfoRequest, ClientRequest clientRequest);
}
