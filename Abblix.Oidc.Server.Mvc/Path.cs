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
