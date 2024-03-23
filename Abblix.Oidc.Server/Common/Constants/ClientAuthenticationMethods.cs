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

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// This class defines various client authentication methods used in OAuth 2.0.
/// </summary>
public static class ClientAuthenticationMethods
{
	/// <summary>
	/// Client authenticates with the authorization server using the client ID and secret via HTTP Basic Authentication.
	/// </summary>
	public const string ClientSecretBasic = "client_secret_basic";

	/// <summary>
	/// Similar to ClientSecretBasic, but the client secret is sent in the request body.
	/// </summary>
	public const string ClientSecretPost = "client_secret_post";

	/// <summary>
	/// The client uses a JWT (JSON Web Token) as a client assertion to authenticate.
	/// </summary>
	public const string ClientSecretJwt = "client_secret_jwt";

	/// <summary>
	/// Similar to ClientSecretJwt, but it uses a private key to sign the JWT.
	/// </summary>
	public const string PrivateKeyJwt = "private_key_jwt";

	/// <summary>
	/// Indicates that no client authentication is for the OAuth request.
	/// </summary>
	public const string None = "none";
}
