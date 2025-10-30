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
	Task<Result<ValidUserInfoRequest, AuthError>> ValidateAsync(UserInfoRequest userInfoRequest, ClientRequest clientRequest);
}
