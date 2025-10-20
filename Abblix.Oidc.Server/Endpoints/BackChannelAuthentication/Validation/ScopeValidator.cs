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
using Abblix.Oidc.Server.Features.ScopeManagement;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates the scopes in OAuth 2.0 authorization requests for backchannel authentication.
/// This validator ensures that the requested scopes are allowed based on the client's configuration
/// and the type of OAuth flow being used. It checks for scope compatibility and prevents unauthorized
/// or excessive scope requests, reinforcing the security policies and minimizing scope-related vulnerabilities.
/// </summary>
/// <param name="scopeManager">The scope manager used to validate scopes.</param>
public class ScopeValidator(IScopeManager scopeManager) : IBackChannelAuthenticationContextValidator
{
	/// <summary>
	/// Validates the scopes in the context of the backchannel authentication request, checking if
	/// they align with the client's permissions and the OAuth flow. This method prevents the client
	/// from requesting unauthorized scopes, such as offline access,
	/// unless explicitly allowed by the client's configuration.
	/// </summary>
	/// <param name="context">The validation context that includes details about the request and the client.</param>
	/// <returns>
	/// A <see cref="RequestError"/> if the scope validation fails,
	/// or null if the scopes in the request are valid.
	/// </returns>
	public Task<RequestError?> ValidateAsync(
		BackChannelAuthenticationValidationContext context)
	{
		return Task.FromResult(Validate(context));
	}

	/// <summary>
	/// Performs the actual scope validation, ensuring the requested scopes are permitted for the client.
	/// It checks for issues like unauthorized offline access requests and verifies the compatibility of
	/// the requested scopes with the client's registered permissions and the resources requested.
	/// </summary>
	/// <param name="context">
	/// Contains the authorization request and the client information necessary for validation.</param>
	/// <returns>
	/// A <see cref="RequestError"/> if the requested scopes are not valid or not allowed,
	/// or null if the validation passes.
	/// </returns>
	private RequestError? Validate(BackChannelAuthenticationValidationContext context)
	{
		if (context.Request.Scope.Contains(Scopes.OfflineAccess) &&
		    context.ClientInfo.OfflineAccessAllowed != true)
		{
			return new RequestError(
				ErrorCodes.InvalidScope,
				"This client is not allowed to request for offline access");
		}

		if (!scopeManager.Validate(
			    context.Request.Scope,
			    context.Resources,
			    out var scopeDefinitions,
			    out var errorDescription))
		{
			return new RequestError(
				ErrorCodes.InvalidScope, errorDescription);
		}

		context.Scope = scopeDefinitions;
		return null;
	}
}
