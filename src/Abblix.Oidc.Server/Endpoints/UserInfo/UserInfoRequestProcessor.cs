// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Utils;


namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// Default <see cref="IUserInfoRequestProcessor"/>: assembles the UserInfo claims set from
/// <see cref="IUserClaimsProvider"/>, filtered by the access token's authorized scopes and any
/// <c>userinfo</c> entry of the OIDC Core §5.5 <c>claims</c> request. Returns
/// <see cref="ErrorCodes.InvalidToken"/> if no claims are produced for the subject.
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
			return new OidcError(ErrorCodes.InvalidToken, "The user claims aren't found");

		var issuer = LicenseChecker.CheckIssuer(issuerProvider.GetIssuer());
		return new UserInfoFoundResponse(userInfo, request.ClientInfo, issuer);
	}
}
