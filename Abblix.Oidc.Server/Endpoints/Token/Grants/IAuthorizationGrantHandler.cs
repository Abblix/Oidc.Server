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
	Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo);
}
