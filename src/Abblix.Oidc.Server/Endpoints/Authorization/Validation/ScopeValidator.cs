// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ScopeManagement;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the scopes specified in the OAuth 2.0 authorization request.
/// This class checks if the requested scopes are permissible based on the client's
/// configuration and the OAuth flow type in use. It ensures that only allowed scopes
/// are requested, enhancing security and compliance with the defined authorization policies.
/// </summary>
/// <param name="scopeManager">The scope manager used to validate scopes.</param>
public class ScopeValidator(IScopeManager scopeManager) : SyncAuthorizationContextValidatorBase
{
	/// <summary>
	/// Validates the scopes specified in the authorization request. It checks the compatibility of requested scopes
	/// with the client's allowed scopes and the OAuth flow type. For instance, it validates if offline access is
	/// requested appropriately and if the client is authorized for such access, and ignores it where OpenID Connect
	/// Core 1.0, section 11, has the server do so.
	/// </summary>
	/// <param name="context">The validation context containing client information and request details.</param>
	/// <returns>
	/// An <see cref="AuthorizationRequestValidationError" /> if the scope validation fails,
	/// or null if the scopes in the request are valid.
	/// </returns>
	protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
	{
		if (context.Request.Scope.Contains(Scopes.OfflineAccess))
	    {
		    if (context.ClientInfo.OfflineAccessAllowed != true)
				    return context.InvalidScope("This client is not allowed to request for offline access");

		    // Ignored as if never asked for, so the host's consent provider, reading the request, is not shown it
		    if (!OfflineAccessGranted(context))
		    {
			    context.Request = context.Request with
			    {
				    Scope = [.. context.Request.Scope.Where(value => value != Scopes.OfflineAccess)],
			    };
		    }
	    }

		if (!scopeManager.Validate(
			    context.Request.Scope,
			    context.Resources,
			    context.ClientInfo.AllowedScopes,
			    out var scopeDefinitions,
			    out var errorDescription))
		{
			return context.InvalidScope(errorDescription);
		}

	    context.Scope = scopeDefinitions;
        return null;
    }

	/// <summary>
	/// Whether the request is processed with the <c>offline_access</c> it asks for, rather than with that scope
	/// ignored, as OpenID Connect Core 1.0, section 11, has the server ignore it unless the response returns an
	/// authorization code, and unless the request asks for consent with <c>prompt=consent</c> or the client is
	/// configured to receive offline access without it.
	/// </summary>
	private static bool OfflineAccessGranted(AuthorizationValidationContext context)
		=> context.FlowType.HasFlag(FlowTypes.AuthorizationCode)
		   && (context.Request.Prompt?.Contains(Prompts.Consent, StringComparer.Ordinal) is true
		       || context.ClientInfo.OfflineAccessWithoutConsentPrompt);
}
