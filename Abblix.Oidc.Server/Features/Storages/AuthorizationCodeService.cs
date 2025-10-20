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
public class AuthorizationCodeService(
	IAuthorizationCodeGenerator authorizationCodeGenerator,
	IEntityStorage storage) : IAuthorizationCodeService
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
			ToKeyString(authorizationCode),
			authorizedGrant,
			new StorageOptions { AbsoluteExpirationRelativeToNow = authorizationCodeExpiresIn });

		return authorizationCode;
	}

	/// <summary>
	/// Validates and processes an authorization code, ensuring it is correct and has not expired or been used previously.
	/// </summary>
	/// <param name="authorizationCode">The authorization code to validate and process.</param>
	/// <returns>A task that resolves to a <see cref="Result<AuthorizedGrant, RequestError>"/>, which indicates the outcome of
	/// the authorization attempt and contains any tokens issued.</returns>
	public async Task<Result<AuthorizedGrant, RequestError>> AuthorizeByCodeAsync(string authorizationCode)
	{
		var result = await storage.GetAsync<AuthorizedGrant>(ToKeyString(authorizationCode), false);
		if (result == null)
		{
			return new RequestError(ErrorCodes.InvalidGrant, "Authorization code is invalid");
		}

		return result;
	}

	/// <summary>
	/// Removes an authorization code from storage, ensuring that it cannot be reused.
	/// </summary>
	/// <param name="authorizationCode">The authorization code to remove.</param>
	/// <returns>A task representing the asynchronous operation to remove the code.</returns>
	public Task RemoveAuthorizationCodeAsync(string authorizationCode)
		=> storage.RemoveAsync(ToKeyString(authorizationCode));

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
			ToKeyString(authorizationCode),
			authorizedGrant,
			new StorageOptions { AbsoluteExpirationRelativeToNow = authorizationCodeExpiresIn }
		);
	}

	/// <summary>
	/// Converts an authorization code into a standardized key string for use in storage.
	/// </summary>
	/// <param name="authorizationCode">The authorization code to convert.</param>
	/// <returns>A string that represents the standardized key for the authorization code.</returns>
	private static string ToKeyString(string authorizationCode) => $"{nameof(authorizationCode)}:{authorizationCode}";
}
