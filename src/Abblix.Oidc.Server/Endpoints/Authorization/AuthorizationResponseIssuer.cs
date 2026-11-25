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
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;
using Microsoft.Extensions.Logging;
using AuthorizationResponse = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse;

namespace Abblix.Oidc.Server.Endpoints.Authorization;

/// <summary>
/// Issues what each requested response type of an authorized request asks for, once the end user's session and the
/// authorization are settled, and records the tokens it hands out.
/// </summary>
/// <param name="sessionClients">The record of which clients a session has.</param>
/// <param name="clock">Tells when the grant was authorized.</param>
/// <param name="responseBuilders">Build each response type's part.</param>
/// <param name="logger">The logger of the processor the tokens handed out are recorded under.</param>
/// <param name="fingerprints">Stands for the subject in that record.</param>
internal sealed class AuthorizationResponseIssuer(
	ISessionClientRegistry sessionClients,
	TimeProvider clock,
	IEnumerable<IAuthorizationResponseBuilder> responseBuilders,
	ILogger logger,
	CredentialFingerprints fingerprints)
{
	private readonly IssuedTokensLog _issuedTokens = new(logger, fingerprints);

	// The ID token hashes the code and the access token issued beside it (OpenID Connect Core 1.0 sections 3.3.2.11
	// and 3.2.2.10), so its builder runs after the others. Ordered here rather than left to registration order, which
	// puts it ahead of the code builder for a host that enables the Implicit Flow before the core registration.
	private readonly IAuthorizationResponseBuilder[] _responseBuilders =
	[
		..responseBuilders.OrderBy(builder => builder.ResponseType == ResponseTypes.IdToken),
	];

	/// <summary>
	/// Records the client for the session and issues what each requested response type asks for.
	/// </summary>
	public async Task<AuthorizationResponse> IssueAsync(
		TenantDefinition tenant,
		ValidAuthorizationRequest request,
		AuthSession authSession,
		AuthorizationContext authContext,
		string[]? responseType)
	{
		// Recorded before anything is issued, so a store that refuses the record fails the authorization
		// rather than following a code or a token already handed out.
		await sessionClients.AddClientAsync(tenant, authSession.SessionId, request.ClientInfo.ClientId);

		// Initialize a successful authentication result. GrantedScopes carries the consent-narrowed
		// scope set (identical to what the issued token carries) so the response encoder advertises the
		// granted scope on the front-channel scope parameter, not the broader requested set (RFC 6749 section 3.3)
		var result = new SuccessfullyAuthenticated(
			request.Model,
			request.ResponseMode,
			authSession.SessionId,
			[..await sessionClients.GetClientsAsync(tenant, authSession.SessionId)])
		{
			GrantedScopes = authContext.Scope,
			SessionPersistence = authSession.Persistence,
		};

		var authorizedGrant = new AuthorizedGrant(authSession, authContext) { AuthorizedAt = clock.GetUtcNow() };

		// Dispatch each requested response-type part to its registered builder. Parts whose builders are not
		// registered (e.g. token / id_token when Implicit Flow is not enabled) cannot reach this point:
		// FlowTypeValidator rejects the request earlier with unsupported_response_type.
		foreach (var builder in _responseBuilders)
		{
			if (!responseType.HasFlag(builder.ResponseType))
				continue;

			if (await builder.BuildResponseAsync(tenant, request, authorizedGrant, result) is { } refusal)
				return refusal;
		}

		// Recorded once every part is built, so a response refused by a later builder is never recorded as answered
		_issuedTokens.ThroughFrontChannel(tenant, request, authSession, result);

		// Return the final authorization result containing codes and tokens as needed.
		return result;
	}
}
