// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
