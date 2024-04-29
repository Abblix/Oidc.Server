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
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Provides services for managing the lifecycle of OAuth 2.0 authorization codes. This service generates, stores,
/// validates, and deletes authorization codes as part of the authorization code grant flow.
/// </summary>
public class AuthorizationCodeService : IAuthorizationCodeService
{
	/// <summary>
	/// Initializes a new instance of the <see cref="AuthorizationCodeService"/> class,
	/// configuring it with the necessary components for authorization code generation and storage.
	/// </summary>
	/// <param name="authorizationCodeGenerator">The generator that creates unique authorization codes.</param>
	/// <param name="storage">The storage mechanism for persisting and retrieving authorization codes and their
	/// associated data.</param>
	public AuthorizationCodeService(
		IAuthorizationCodeGenerator authorizationCodeGenerator,
		IEntityStorage storage)
	{
		_authorizationCodeGenerator = authorizationCodeGenerator;
		_storage = storage;
	}

	private readonly IAuthorizationCodeGenerator _authorizationCodeGenerator;
	private readonly IEntityStorage _storage;

	/// <summary>
	/// Generates a unique authorization code for a given authentication session and authorization request context.
	/// This code is subsequently used by the client to request an access token.
	/// </summary>
	/// <param name="authSession">The authentication session that captures the current user's session state.</param>
	/// <param name="context">The context of the authorization request, including any scopes and parameters specified
	/// by the client.</param>
	/// <param name="clientInfo">Information about the client making the authorization request, used to determine
	/// settings like code expiration.</param>
	/// <returns>A task that resolves to the generated authorization code as a string.</returns>
	public async Task<string> GenerateAuthorizationCodeAsync(
		AuthSession authSession,
		AuthorizationContext context,
		ClientInfo clientInfo)
	{
		var authorizationCode = _authorizationCodeGenerator.GenerateAuthorizationCode();
		
		await _storage.SetAsync(
			ToKeyString(authorizationCode),
			new AuthorizedGrantResult(authSession, context),
			new StorageOptions { AbsoluteExpirationRelativeToNow = clientInfo.AuthorizationCodeExpiresIn });
		
		return authorizationCode;
	}

	/// <summary>
	/// Validates and processes an authorization code, ensuring it is correct and has not expired or been used previously.
	/// </summary>
	/// <param name="authorizationCode">The authorization code to validate and process.</param>
	/// <returns>A task that resolves to a <see cref="GrantAuthorizationResult"/>, which indicates the outcome of
	/// the authorization attempt and contains any tokens issued.</returns>
	public async Task<GrantAuthorizationResult> AuthorizeByCodeAsync(string authorizationCode)
	{
		var result = await _storage.GetAsync<GrantAuthorizationResult>(ToKeyString(authorizationCode), false);
		if (result == null)
		{
			return new InvalidGrantResult(ErrorCodes.InvalidGrant, "Authorization code is invalid");
		}

		return result;
	}

	/// <summary>
	/// Removes an authorization code from storage, ensuring that it cannot be reused.
	/// </summary>
	/// <param name="authorizationCode">The authorization code to remove.</param>
	/// <returns>A task representing the asynchronous operation to remove the code.</returns>
	public Task RemoveAuthorizationCodeAsync(string authorizationCode)
		=> _storage.RemoveAsync(ToKeyString(authorizationCode));

	private string ToKeyString(string authorizationCode) => $"{nameof(authorizationCode)}:{authorizationCode}";
}
