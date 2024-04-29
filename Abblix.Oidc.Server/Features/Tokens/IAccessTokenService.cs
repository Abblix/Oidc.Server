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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.UserAuthentication;

namespace Abblix.Oidc.Server.Features.Tokens;

/// <summary>
/// Defines operations related to access tokens, including their creation and authentication.
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
	Task<EncodedJsonWebToken> CreateAccessTokenAsync(AuthSession authSession,
		AuthorizationContext authContext,
		ClientInfo clientInfo);

	/// <summary>
	/// Asynchronously authenticates a user based on a provided access token.
	/// </summary>
	/// <param name="accessToken">The access token to authenticate.</param>
	/// <returns>A task that represents the asynchronous authentication operation. The task result contains
	/// the <see cref="AuthSession"/> and <see cref="AuthorizationContext"/> associated with the authenticated user.</returns>
	Task<(AuthSession, AuthorizationContext)> AuthenticateByAccessTokenAsync(JsonWebToken accessToken);
}
