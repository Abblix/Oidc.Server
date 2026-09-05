// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Issues OAuth 2.0 access tokens as signed JWTs (RFC 9068 access-token format) and reverses
/// the mapping by reconstructing the originating <see cref="AuthSession"/> and
/// <see cref="AuthorizationContext"/> from the token's claims.
/// </summary>
public interface IAccessTokenService
{
	/// <summary>
	/// Asynchronously creates a new access token based on the given authentication session, authorization context
	/// and client information.
	/// </summary>
	/// <param name="authSession">The authentication session containing user and session details.</param>
	/// <param name="authContext">The authorization context containing details about the granted permissions and scopes.</param>
	/// <param name="clientInfo">Information about the client for whom the token is being created.</param>
	/// <returns>A task that represents the asynchronous create operation.
	/// The task result contains the newly created <see cref="JsonWebToken"/>.</returns>
	Task<EncodedJsonWebToken> CreateAccessTokenAsync(
		AuthSession authSession,
		AuthorizationContext authContext,
		ClientInfo clientInfo);

	/// <summary>
	/// Asynchronously authenticates a user based on a provided access token.
	/// </summary>
	/// <param name="accessToken">The access token to authenticate.</param>
	/// <param name="clientInfo">The client the token was issued for; its sector opens a pairwise subject back to
	/// the real subject.</param>
	/// <returns>A task that represents the asynchronous authentication operation. On success the result carries the
	/// <see cref="AuthorizedGrant"/> (the authenticated user's session and authorization context); it carries an
	/// <see cref="OidcError"/> when a pairwise subject cannot be opened for this client, so the caller rejects the
	/// token at the protocol level. This mirrors the result shape of the refresh and token-exchange recovery paths.</returns>
	Task<Result<AuthorizedGrant, OidcError>> AuthenticateByAccessTokenAsync(
		JsonWebToken accessToken,
		ClientInfo clientInfo);
}
