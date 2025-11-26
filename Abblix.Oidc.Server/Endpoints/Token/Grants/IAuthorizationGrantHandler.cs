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
/// Defines the interface for handling specific types of authorization grants within an OAuth 2.0 or OpenID Connect
/// context. Implementations of this interface are responsible for processing authorization requests based on
/// the supported grant type, validating the request, and generating appropriate authorization responses.
/// </summary>
public interface IAuthorizationGrantHandler : IGrantTypeInformer
{
	/// <summary>
	/// Processes an authorization request asynchronously, validates the request against the supported grant type,
	/// and generates a response indicating the authorization result.
	/// </summary>
	/// <param name="request">The authorization request containing the required parameters for the grant type.</param>
	/// <param name="clientInfo">Client information associated with the request, used for validation and
	/// to generate the authorization response.</param>
	/// <returns>A task that returns a <see cref="Result{AuthorizedGrant, AuthError}"/> with the authorization outcome,
	/// including any tokens or error messages.</returns>
	Task<Result<AuthorizedGrant, OidcError>> AuthorizeAsync(TokenRequest request, ClientInfo clientInfo);
}
