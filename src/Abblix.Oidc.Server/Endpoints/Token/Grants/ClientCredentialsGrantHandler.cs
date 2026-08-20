// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.RandomGenerators;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;

/// <summary>
/// Handles the authorization process for the client credentials grant type within the OAuth 2.0 framework.
/// This grant type is designed for machine-to-machine (M2M) authentication where the client itself is the resource owner.
/// There is no end-user involved in this flow - the client uses its own credentials to obtain an access token
/// directly from the authorization server.
/// </summary>
/// <remarks>
/// The client credentials grant type is specified in RFC 6749 Section 4.4.
/// It is typically used in scenarios such as:
/// - Backend services accessing APIs
/// - Scheduled jobs or automated tasks
/// - Microservice-to-microservice communication
/// - CI/CD pipelines
/// The client must authenticate itself before this handler is invoked, using methods such as
/// client_secret_basic, client_secret_post, or private_key_jwt.
/// </remarks>
/// <param name="sessionIdGenerator">Generates unique session identifiers for authentication sessions.</param>
/// <param name="timeProvider">Provides access to the current time for session timestamps.</param>
public class ClientCredentialsGrantHandler(
	ISessionIdGenerator sessionIdGenerator,
	TimeProvider timeProvider) : IAuthorizationGrantHandler
{
	/// <summary>
	/// Specifies the grant type that this handler supports, which is the "client_credentials" grant type.
	/// This ensures that this handler is only invoked when processing requests with the client credentials grant type.
	/// </summary>
	public IEnumerable<string> GrantTypesSupported
	{
		get { yield return GrantTypes.ClientCredentials; }
	}

	/// <summary>
	/// Asynchronously processes the token request using the client credentials grant type.
	/// Since the client has already been authenticated (via client authentication middleware),
	/// this handler creates a grant for the client with the requested scope.
	/// </summary>
	/// <param name="request">The token request containing the requested scope and other parameters.</param>
	/// <param name="clientInfo">Information about the authenticated client making the request.</param>
	/// <returns>A task that completes with an authorized grant containing the client session and context.</returns>
	/// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
	public Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo, CancellationToken cancellationToken)
	{
		// Extract the requested scope from the request (may be null/empty)
		var scope = request.Scope;

		// Create an authorization context for the client with the requested scope.
		// client_credentials is a direct grant: the token request itself IS the authorization, so
		// the RFC 8707 resource indicators are the authorized audience and are passed to the context
		// so they reach the issued token's aud claim. The resource validator has already rejected
		// any unregistered target with invalid_target before this handler runs.
		var context = new AuthorizationContext(clientInfo.ClientId, scope, null, request.Resources);

		// Create an authentication session representing the client (not a user)
		// In client credentials flow, the client itself is the "subject"
		var authSession = new AuthSession(
			Subject: clientInfo.ClientId,
			SessionId: sessionIdGenerator.GenerateSessionId(),
			AuthenticationTime: timeProvider.GetUtcNow(),
			IdentityProvider: GrantTypes.ClientCredentials)
		{
			AffectedClientIds = { clientInfo.ClientId }
		};

		// Create and return the authorized grant
		var grant = new AuthorizedGrant(authSession, context);
		return Task.FromResult<Result<AuthorizedGrant, OidcError>>(grant);
	}
}
