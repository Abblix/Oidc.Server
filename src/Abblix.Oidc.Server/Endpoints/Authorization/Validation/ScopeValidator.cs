// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;

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
	/// with the client's allowed scopes and the OAuth flow type. Offline access is ignored where OpenID Connect
	/// Core 1.0 has the server do so, and refused only when it would otherwise be received by a client not
	/// allowed it.
	/// </summary>
	/// <param name="tenant">The tenant the request is served at.</param>
	/// <param name="context">The validation context containing client information and request details.</param>
	/// <returns>
	/// An <see cref="AuthorizationRequestValidationError" /> if the scope validation fails,
	/// or null if the scopes in the request are valid.
	/// </returns>
	protected override AuthorizationRequestValidationError? Validate(TenantDefinition tenant, AuthorizationValidationContext context)
	{
		// An offline_access the server ignores is set aside before deciding whether the request named a scope at all,
		// so a request naming it alone is served the default on every route, and the resources the resource validator
		// settled before this are those of the same served scope
		var named = context.NamedScope();

		// The request goes on with the scope it is served with, so what follows, the host's consent provider
		// included, reads the default a request naming none was given
		if (context.ServedScope() is not { } scope)
			return context.InvalidScope(ScopeRefusals.NoneNamed);

		// A request coming back from a page already carries the default it was served with, so whether the client
		// named a scope is kept from the first pass rather than read again from a scope that is no longer empty
		context.Request = context.Request with
		{
			Scope = scope,
			ClientNamedNoScope = context.Request.ClientNamedNoScope || named.Length == 0,
		};

		if (context.Request.Scope.Contains(Scopes.OfflineAccess))
		{
			// Ignored as if never asked for, so the host's consent provider, reading the request, is not shown it
			if (!context.OfflineAccessReceived())
			{
				context.Request = context.Request with
				{
					Scope = [.. context.Request.Scope.Where(value => value != Scopes.OfflineAccess)],
				};
			}
			else if (!context.ClientInfo.OfflineAccess.IsAllowed())
			{
				return context.InvalidScope("This client is not allowed to request for offline access");
			}
		}

		if (!scopeManager.Validate(tenant, 
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
}
