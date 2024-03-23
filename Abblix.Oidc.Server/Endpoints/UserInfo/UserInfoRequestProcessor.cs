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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using UserInfoResponse = Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces.UserInfoResponse;


namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// Processes user information requests, retrieving and formatting user information based on the provided request.
/// This class plays a crucial role in handling requests to the UserInfo endpoint, ensuring that the returned
/// user information adheres to the requested scopes and the OAuth 2.0 and OpenID Connect standards.
/// </summary>
internal class UserInfoRequestProcessor : IUserInfoRequestProcessor
{
	/// <summary>
	/// Initializes a new instance of the <see cref="UserInfoRequestProcessor"/> class.
	/// </summary>
	/// <param name="userInfoProvider">Provider for user information based on JWT claims. This component is responsible
	/// for fetching user-related data that can be returned to the client.</param>
	/// <param name="scopeClaimsProvider">Provider for determining which claims to include in the response based on the
	/// authorization context and requested scopes. This ensures that only the claims the client is authorized to receive
	/// are included.</param>
	/// <param name="subjectTypeConverter">Converter for transforming subject identifiers (sub claims) based on client
	/// requirements, supporting privacy and client-specific identifier formats.</param>
	/// <param name="issuerProvider">Provider for the issuer URL, used in generating fully qualified claim names and ensuring
	/// consistency in the issuer claim across responses.</param>
	public UserInfoRequestProcessor(
		IUserInfoProvider userInfoProvider,
		IScopeClaimsProvider scopeClaimsProvider,
		ISubjectTypeConverter subjectTypeConverter,
		IIssuerProvider issuerProvider)
	{
		_userInfoProvider = userInfoProvider;
		_scopeClaimsProvider = scopeClaimsProvider;
		_subjectTypeConverter = subjectTypeConverter;
		_issuerProvider = issuerProvider;
	}

	private readonly IUserInfoProvider _userInfoProvider;
	private readonly IScopeClaimsProvider _scopeClaimsProvider;
	private readonly ISubjectTypeConverter _subjectTypeConverter;
	private readonly IIssuerProvider _issuerProvider;

	/// <summary>
	/// Asynchronously processes a valid user information request and returns a response with the requested user information.
	/// </summary>
	/// <param name="request">The valid user info request to process.</param>
	/// <returns>A <see cref="Task"/> representing the asynchronous operation,
	/// which upon completion will yield a <see cref="UserInfoResponse"/>.</returns>
	public async Task<UserInfoResponse> ProcessAsync(ValidUserInfoRequest request)
	{
		var claimNames = _scopeClaimsProvider.GetRequestedClaims(
			request.AuthContext.Scope,
			request.AuthContext.RequestedClaims?.UserInfo);

		var userInfo = await _userInfoProvider.GetUserInfoAsync(request.AuthSession.Subject, claimNames);
		if (userInfo == null)
			return new UserInfoErrorResponse(ErrorCodes.InvalidGrant, "The user is not found");

		var subject = _subjectTypeConverter.Convert(request.AuthSession.Subject, request.ClientInfo);
		userInfo.SetProperty(JwtClaimTypes.Subject, subject);

		var issuer = LicenseChecker.CheckLicense(_issuerProvider.GetIssuer());
		return new UserInfoFoundResponse(userInfo, request.ClientInfo, issuer);
	}
}
