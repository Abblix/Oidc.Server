// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.UserInfo;
using UserInfoResponse = Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces.UserInfoResponse;


namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// Processes user information requests by retrieving and formatting user information based on the provided request.
/// This class is integral in handling requests to the UserInfo endpoint, ensuring that the returned user information
/// adheres to requested scopes and complies with OAuth 2.0 and OpenID Connect standards.
/// </summary>
internal class UserInfoRequestProcessor : IUserInfoRequestProcessor
{
	/// <summary>
	/// Initializes a new instance of the <see cref="UserInfoRequestProcessor"/> class.
	/// </summary>
	/// <param name="issuerProvider">Provider for the issuer URL, which is essential for generating fully qualified
	/// claim names and ensuring consistency in the 'iss' claim across responses.</param>
	/// <param name="userClaimsProvider">Provider for user claims based on JWT claims.
	/// This component fetches user-related data that can be returned to the client, tailored to the client's
	/// authorization context and scope.</param>
	public UserInfoRequestProcessor(IIssuerProvider issuerProvider, IUserClaimsProvider userClaimsProvider)
	{
		_issuerProvider = issuerProvider;
		_userClaimsProvider = userClaimsProvider;
	}

	private readonly IIssuerProvider _issuerProvider;
	private readonly IUserClaimsProvider _userClaimsProvider;

	/// <summary>
	/// Asynchronously processes a valid user information request and returns a structured response containing
	/// the requested user information.
	/// </summary>
	/// <param name="request">The valid user information request containing the authentication session,
	/// authorization context and client information necessary to determine the scope and specifics of
	/// the requested claims.</param>
	/// <returns>A <see cref="Task"/> representing the asynchronous operation,
	/// which upon completion will yield a <see cref="UserInfoResponse"/> encapsulating either the user's claims
	/// or an error response.</returns>
	public async Task<UserInfoResponse> ProcessAsync(ValidUserInfoRequest request)
	{
		var userInfo = await _userClaimsProvider.GetUserClaimsAsync(
			request.AuthSession,
			request.AuthContext.Scope,
			request.AuthContext.RequestedClaims?.UserInfo,
			request.ClientInfo);

		if (userInfo == null)
			return new UserInfoErrorResponse(ErrorCodes.InvalidGrant, "The user claims aren't found");

		var issuer = LicenseChecker.CheckIssuer(_issuerProvider.GetIssuer());
		return new UserInfoFoundResponse(userInfo, request.ClientInfo, issuer);
	}
}
