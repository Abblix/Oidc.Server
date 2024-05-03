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

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Contains constants for various OpenID Connect and OAuth2 endpoint paths.
/// This class centralizes the paths used throughout the application for consistency and maintainability.
/// </summary>
public static class Path
{
    private const string Base = "~/connect";

    /// <summary>
    /// Path for the authorization endpoint.
    /// </summary>
    public const string Authorize = Base + "/authorize";

    /// <summary>
    /// Path for the pushed authorization request (PAR) endpoint.
    /// </summary>
    public const string PushAuthorizationRequest = Base + "/par";

    /// <summary>
    /// Path for the user information endpoint.
    /// </summary>
    public const string UserInfo = Base + "/userinfo";

    /// <summary>
    /// Path for the end session endpoint.
    /// </summary>
    public const string EndSession = Base + "/endsession";

    /// <summary>
    /// Path for the session checking endpoint.
    /// </summary>
    public const string CheckSession = Base + "/checksession";

    /// <summary>
    /// Path for the token endpoint.
    /// </summary>
    public const string Token = Base + "/token";

    /// <summary>
    /// Path for the token revocation endpoint.
    /// </summary>
    public const string Revocation = Base + "/revoke";

    /// <summary>
    /// Path for the token introspection endpoint.
    /// </summary>
    public const string Introspection = Base + "/introspect";

    /// <summary>
    /// Path for the backchannel authentication endpoint.
    /// </summary>
    public const string BackchannelAuthentication = Base + "/ciba";

    /// <summary>
    /// Path for the device authorization endpoint.
    /// </summary>
    public const string DeviceAuthorization = Base + "/deviceauthorization";

    /// <summary>
    /// Path for the client registration endpoint.
    /// </summary>
    public const string Register = Base + "/register";

    /// <summary>
    /// Path for the OpenID configuration document.
    /// </summary>
    public const string Configuration = "~/.well-known/openid-configuration";

    /// <summary>
    /// Path for the JSON Web Key Set (JWKS) endpoint.
    /// </summary>
    public const string Keys = "~/.well-known/jwks";
}
