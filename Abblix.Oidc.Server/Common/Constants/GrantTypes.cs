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
/// Represents OAuth 2.0 grant types.
/// </summary>
public static class GrantTypes
{
    /// <summary>
    /// Represents the Authorization Code grant type. Used when a client wants to exchange an authorization code
    /// for an access token. Commonly used in web applications with server-side backends.
    /// </summary>
    public const string AuthorizationCode = "authorization_code";

    /// <summary>
    /// Represents the Client Credentials grant type. Used when a client requests an access token using its
    /// own credentials. Suitable for machine-to-machine communication.
    /// </summary>
    public const string ClientCredentials = "client_credentials";

    /// <summary>
    /// Represents the Refresh Token grant type. Used to obtain a new access token using a refresh token.
    /// Helpful for maintaining user sessions without requiring reauthentication.
    /// </summary>
    public const string RefreshToken = "refresh_token";

    /// <summary>
    /// Represents the Implicit grant type. Used in single-page applications to obtain access tokens directly
    /// from the authorization endpoint. Suitable for browser-based applications.
    /// </summary>
    public const string Implicit = "implicit";

    /// <summary>
    /// Represents the Password grant type. Allows clients to exchange a username and password for an access token.
    /// Should be used with caution due to potential security risks.
    /// </summary>
    public const string Password = "password";

    /// <summary>
    /// Represents the CIBA (Client Initiated Backchannel Authentication) grant type.
    /// Used for authentication with minimal user interaction, often in use cases like strong customer authentication.
    /// </summary>
    public const string Ciba = "urn:openid:params:grant-type:ciba";

    /// <summary>
    /// Represents the JWT Bearer grant type. Allows clients to request access tokens using a JWT
    /// (JSON Web Token) assertion. Useful for securing API-to-API communication.
    /// </summary>
    public const string JwtBearer = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    /// <summary>
    /// Represents the Device Authorization grant type. This grant type is used in scenarios where the client device
    /// lacks a browser or has limited input capabilities, allowing it to obtain user authorization from another device
    /// with better input capabilities. It is particularly useful for devices in the IoT (Internet of Things) sector
    /// and smart devices that require user interaction for authorization.
    /// </summary>
    public const string DeviceAuthorization = "urn:ietf:params:oauth:grant-type:device_code";
}
