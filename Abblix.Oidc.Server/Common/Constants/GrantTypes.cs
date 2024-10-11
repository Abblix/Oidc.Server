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
    /// Represents the Refresh Token grant type. Used to get a new access token using a refresh token.
    /// Helpful for maintaining user sessions without requiring re-authentication.
    /// </summary>
    public const string RefreshToken = "refresh_token";

    /// <summary>
    /// Represents the Implicit grant type. Used in single-page applications to get access tokens directly
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
    /// lacks a browser or has limited input capabilities, allowing it to get user authorization from another device
    /// with better input capabilities. It is particularly useful for devices in the IoT (Internet of Things) sector
    /// and smart devices that require user interaction for authorization.
    /// </summary>
    public const string DeviceAuthorization = "urn:ietf:params:oauth:grant-type:device_code";
}
