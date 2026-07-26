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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Endpoints.Token.Grants;


/// <summary>
/// Strategy contract for resolving the <c>grant_type</c>-specific portion of an OAuth 2.0 token
/// request (RFC 6749 §4) into an <see cref="AuthorizedGrant"/>: an authentication session plus the
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
	[Obsolete("Implement and call the overload taking a CancellationToken. This one is kept so an existing " +
	          "implementation keeps working, and will be removed in the next major version.")]
	Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo)
		=> AuthorizeAsync(request, clientInfo, CancellationToken.None);

	/// <inheritdoc cref="AuthorizeAsync(TokenRequest, ClientInfo)"/>
	/// <param name="request">The token request (already authenticated against the client).</param>
	/// <param name="clientInfo">The authenticated client.</param>
	/// <param name="cancellationToken">
	/// Abandons the resolution when the caller stops waiting. CIBA holds this call open for the configured
	/// long-polling timeout, so a handler that never receives the token goes on polling storage for a client
	/// that disconnected.
	/// </param>
	/// <remarks>
	/// This is the member an implementation provides. The obsolete overload above defaults to forwarding here,
	/// so a caller still holding the old signature keeps working, while an implementation that provided only
	/// the old one fails to compile rather than silently never receiving the token.
	/// </remarks>
	Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(
		TokenRequest request, ClientInfo clientInfo, CancellationToken cancellationToken);
}
