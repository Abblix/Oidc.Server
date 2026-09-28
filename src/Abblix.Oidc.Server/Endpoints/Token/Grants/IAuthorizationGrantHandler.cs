// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;


/// <summary>
/// Strategy contract for resolving the <c>grant_type</c>-specific portion of an OAuth 2.0 token
/// request (RFC 6749 section 4) into an <see cref="AuthorizedGrant"/>: an authentication session plus the
/// <see cref="AuthorizationContext"/> (subject, scope, resources, claims) that the issued tokens
/// will inherit. Each implementation advertises the grant types it owns via
/// <see cref="IGrantTypeInformer.GrantTypesSupported"/>.
/// </summary>
public interface IAuthorizationGrantHandler : IGrantTypeInformer
{
	/// <summary>
	/// Resolves the grant-specific input from <paramref name="request"/> (authorization code,
	/// refresh token, device code, client credentials, JWT assertion, etc.) into the
	/// <see cref="AuthorizedGrant"/> that will drive token issuance, or an <see cref="OidcError"/>
	/// such as <c>invalid_grant</c>, <c>authorization_pending</c>, or <c>slow_down</c>.
	/// </summary>
	/// <param name="request">The token request (already authenticated against the client).</param>
	/// <param name="clientInfo">The authenticated client; used to enforce that the grant was
	/// issued to the same client that is now redeeming it.</param>
	/// <param name="cancellationToken">
	/// Abandons the resolution when the caller stops waiting. CIBA holds this call open for the configured
	/// long-polling timeout, so a handler that never receives the token goes on polling storage for a client
	/// that disconnected. A handler that spends the grant while resolving it - takes a device code or a
	/// backchannel authentication request from storage - does not pass the token past that point: giving up
	/// there would spend the grant and issue nothing (see <see cref="ITokenRequestProcessor"/>). For the same
	/// reason, a refusal that the client is expected to cure by retrying belongs in a validator registered
	/// before the one that calls this, not after it.
	/// </param>
	Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(
		TokenRequest request, ClientInfo clientInfo, CancellationToken cancellationToken);
}
