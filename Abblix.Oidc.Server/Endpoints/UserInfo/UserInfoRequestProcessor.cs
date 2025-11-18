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
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Utils;


namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// Processes user information requests by retrieving and formatting user information based on the provided request.
/// This class is integral in handling requests to the UserInfo endpoint, ensuring that the returned user information
/// adheres to requested scopes and complies with OAuth 2.0 and OpenID Connect standards.
/// </summary>
public class UserInfoRequestProcessor(IIssuerProvider issuerProvider, IUserClaimsProvider userClaimsProvider) : IUserInfoRequestProcessor
{
	/// <summary>
	/// Asynchronously processes a valid user information request and returns a structured response containing
	/// the requested user information.
	/// </summary>
	/// <param name="request">The valid user information request containing the authentication session,
	/// authorization context and client information necessary to determine the scope and specifics of
	/// the requested claims.</param>
	/// <returns>A <see cref="Task"/> representing the asynchronous operation,
	/// which upon completion will yield a <see cref="Result{UserInfoFoundResponse, AuthError}"/> encapsulating either the user's claims
	/// or an error response.</returns>
	public async Task<Result<UserInfoFoundResponse, OidcError>> ProcessAsync(ValidUserInfoRequest request)
	{
		var userInfo = await userClaimsProvider.GetUserClaimsAsync(
			request.AuthSession,
			request.AuthContext.Scope,
			request.AuthContext.RequestedClaims?.UserInfo,
			request.ClientInfo);

		if (userInfo == null)
			return new OidcError(ErrorCodes.InvalidGrant, "The user claims aren't found");

		var issuer = LicenseChecker.CheckIssuer(issuerProvider.GetIssuer());
		return new UserInfoFoundResponse(userInfo, request.ClientInfo, issuer);
	}
}
