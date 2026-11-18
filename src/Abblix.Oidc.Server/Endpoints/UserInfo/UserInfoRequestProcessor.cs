// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.UserInfo.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Utils;


namespace Abblix.Oidc.Server.Endpoints.UserInfo;

/// <summary>
/// Default <see cref="IUserInfoRequestProcessor"/>: assembles the UserInfo claims set from
/// <see cref="IUserClaimsProvider"/>, filtered by the access token's authorized scopes and any
/// <c>userinfo</c> entry of the OIDC Core section 5.5 <c>claims</c> request. Returns
/// <see cref="ErrorCodes.InvalidToken"/> if no claims are produced for the subject.
/// </summary>
public class UserInfoRequestProcessor(
	ITenantCatalog catalog,
	IUserClaimsProvider userClaimsProvider) : IUserInfoRequestProcessor
{
	/// <summary>
	/// Asynchronously processes a valid user information request and returns a structured response containing
	/// the requested user information.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="request">The valid user information request containing the authentication session,
	/// authorization context and client information necessary to determine the scope and specifics of
	/// the requested claims.</param>
	/// <returns>A <see cref="Task"/> representing the asynchronous operation,
	/// which upon completion will yield a <see cref="Result{UserInfoFoundResponse, AuthError}"/> encapsulating either the user's claims
	/// or an error response.</returns>
	public async Task<Result<UserInfoFoundResponse, OidcError>> ProcessAsync(TenantDefinition tenant, ValidUserInfoRequest request)
	{
		var userInfo = await userClaimsProvider.GetUserClaimsAsync(
			tenant,
			request.AuthSession,
			request.AuthContext.Scope,
			request.AuthContext.RequestedClaims?.UserInfo,
			request.ClientInfo);

		if (userInfo == null)
			return new OidcError(ErrorCodes.InvalidToken, "The user claims aren't found");

		// OpenID Connect Core 1.0 section 5.3.2: "If a Claim is not returned, that Claim Name SHOULD be omitted from the
		// JSON object representing the Claims; it SHOULD NOT be present with a null or empty string value."
		var withoutValue = userInfo
			.Where(claim => IsWithoutValue(claim.Value))
			.Select(claim => claim.Key)
			.ToList();

		foreach (var name in withoutValue)
			userInfo.Remove(name);

		var issuer = LicenseChecker.CheckIssuer(tenant.Issuer.OriginalString, tenant, catalog);
		return new UserInfoFoundResponse(userInfo, request.ClientInfo, issuer);
	}

	/// <summary>
	/// A claim the store answered without a value: JSON null, or a string with nothing in it.
	/// </summary>
	private static bool IsWithoutValue(JsonNode? value) => value switch
	{
		null => true,
		JsonValue scalar when scalar.TryGetValue<string>(out var text) => text.Length == 0,
		_ => false,
	};
}
