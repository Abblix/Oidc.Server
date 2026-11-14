// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// The grant a validated JWT Bearer assertion authorizes.
/// </summary>
internal static class JwtBearerGrants
{
	/// <summary>
	/// The grant of the subject <paramref name="ctx"/> names to the client that presented the assertion.
	/// </summary>
	/// <param name="ctx">The validated assertion.</param>
	/// <param name="clientId">The client that presented it.</param>
	/// <param name="scope">The scope requested.</param>
	/// <param name="resources">The resources requested.</param>
	/// <param name="sessionId">The session the grant opens.</param>
	/// <param name="authenticatedAt">When the subject is taken as authenticated.</param>
	public static AuthorizedGrant Of(
		JwtBearerValidationContext ctx,
		string clientId,
		string[] scope,
		Uri[]? resources,
		string sessionId,
		DateTimeOffset authenticatedAt)
	{
		// jwt-bearer is a direct grant: the token request itself IS the authorization, so the
		// RFC 8707 resource indicators are the authorized audience and are passed to the context
		// so they reach the issued token's aud claim. The resource validator has already rejected
		// any unregistered target with invalid_target before this handler runs.
		var context = new AuthorizationContext(clientId, scope, null, resources);

		var authSession = new AuthSession(
			Subject: ctx.Subject,
			SessionId: sessionId,
			AuthenticationTime: authenticatedAt,
			IdentityProvider: ctx.Issuer);

		return new AuthorizedGrant(authSession, context);
	}
}
