// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
	/// A <see cref="OidcError"/> if the scope validation fails,
	/// or null if the scopes in the request are valid.
	/// </returns>
	public Task<OidcError?> ValidateAsync(
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
	/// A <see cref="OidcError"/> if the requested scopes are not valid or not allowed,
	/// or null if the validation passes.
	/// </returns>
	private OidcError? Validate(BackChannelAuthenticationValidationContext context)
	{
		if (context.Request.Scope.Contains(Scopes.OfflineAccess) &&
		    context.ClientInfo.OfflineAccessAllowed != true)
		{
			return new OidcError(
				ErrorCodes.InvalidScope,
				"This client is not allowed to request for offline access");
		}

		if (!scopeManager.Validate(
			    context.Request.Scope,
			    context.Resources,
			    context.ClientInfo.AllowedScopes,
			    out var scopeDefinitions,
			    out var errorDescription))
		{
			return new OidcError(
				ErrorCodes.InvalidScope, errorDescription);
		}

		context.Scope = scopeDefinitions;
		return null;
	}
}
