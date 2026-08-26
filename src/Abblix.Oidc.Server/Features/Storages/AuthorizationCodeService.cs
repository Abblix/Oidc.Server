// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.RandomGenerators;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides services for managing the lifecycle of OAuth 2.0 authorization codes. This service generates, stores,
/// validates, and deletes authorization codes as part of the authorization code grant flow.
/// </summary>
/// <param name="authorizationCodeGenerator">The generator that creates unique authorization codes.</param>
/// <param name="storage">The storage mechanism for persisting and retrieving authorization codes and their
/// associated data.</param>
/// <param name="keyFactory">The factory for generating standardized storage keys.</param>
public class AuthorizationCodeService(
	IAuthorizationCodeGenerator authorizationCodeGenerator,
	IEntityStorage storage,
	IEntityStorageKeyFactory keyFactory) : IAuthorizationCodeService
{
	/// <summary>
	/// Generates a unique authorization code for a given authorization grant result and client information.
	/// The client subsequently uses this code to request an access token.
	/// </summary>
	/// <param name="authorizedGrant">An object encapsulating the result of the authorization grant, including
	/// user authentication session and authorization context details.</param>
	/// <param name="authorizationCodeExpiresIn"></param>
	/// <returns>A task that resolves to the generated authorization code as a string.</returns>
	public async Task<string> GenerateAuthorizationCodeAsync(
		AuthorizedGrant authorizedGrant,
		TimeSpan authorizationCodeExpiresIn)
	{
		var authorizationCode = authorizationCodeGenerator.GenerateAuthorizationCode();

		await storage.SetAsync(
			keyFactory.AuthorizedGrantKey(authorizationCode),
			authorizedGrant,
			new () { AbsoluteExpirationRelativeToNow = authorizationCodeExpiresIn });

		return authorizationCode;
	}

	/// <summary>
	/// Validates and processes an authorization code, ensuring it is correct and has not expired or been used previously.
	/// </summary>
	/// <param name="authorizationCode">The authorization code to validate and process.</param>
	/// <returns>A task that resolves to a <see cref="Result{AuthorizedGrant, AuthError}"/>, which indicates the outcome of
	/// the authorization attempt and contains any tokens issued.</returns>
	public async Task<Result<AuthorizedGrant, OidcError>> AuthorizeByCodeAsync(string authorizationCode)
	{
		var result = await storage.GetAsync<AuthorizedGrant>(keyFactory.AuthorizedGrantKey(authorizationCode), false);
		if (result == null)
		{
			return new OidcError(ErrorCodes.InvalidGrant, "Authorization code is invalid");
		}

		return result;
	}

	/// <inheritdoc />
	public async Task<Result<AuthorizedGrant, OidcError>> RemoveAuthorizationCodeAsync(string authorizationCode)
	{
		// removeOnRetrieval: true performs an atomic get-and-remove, so two concurrent redemptions
		// of the same code cannot both observe the grant - in one process exactly one wins the claim,
		// across processes at most one and never two; every other
		// caller finds the code already gone and is rejected.
		var grant = await storage.GetAsync<AuthorizedGrant>(
			keyFactory.AuthorizedGrantKey(authorizationCode), removeOnRetrieval: true);

		if (grant == null)
		{
			return new OidcError(ErrorCodes.InvalidGrant, "Authorization code is invalid");
		}

		return grant;
	}

	/// <summary>
	/// Updates the authorization grant result based on a specific authorization code and client information.
	/// This method allows the authorization grant to be updated with new information or tokens as needed.
	/// </summary>
	/// <param name="authorizationCode">The authorization code associated with the grant result to update.</param>
	/// <param name="authorizedGrant">The updated authorization grant result containing the latest
	/// authentication and authorization details.</param>
	/// <param name="authorizationCodeExpiresIn"></param>
	/// <returns>A task representing the asynchronous operation of updating the authorization grant result.</returns>
	public Task UpdateAuthorizationGrantAsync(
		string authorizationCode,
		AuthorizedGrant authorizedGrant,
		TimeSpan authorizationCodeExpiresIn)
	{
		return storage.SetAsync(
			keyFactory.AuthorizedGrantKey(authorizationCode),
			authorizedGrant,
			new () { AbsoluteExpirationRelativeToNow = authorizationCodeExpiresIn }
		);
	}
}
