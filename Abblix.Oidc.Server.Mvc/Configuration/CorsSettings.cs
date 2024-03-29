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

namespace Abblix.Oidc.Server.Mvc.Configuration;

/// <summary>
/// Represents the settings for Cross-Origin Resource Sharing (CORS) policy.
/// CORS policies allow web applications to make requests from different domains,
/// enhancing security by restricting cross-origin requests.
/// </summary>
public record CorsSettings
{
    /// <summary>
    /// A list of origins that are allowed to make requests to the resource,
    /// enhancing security by limiting cross-origin interactions.
    /// </summary>
    public string[]? AllowedOrigins { get; init; }

    /// <summary>
    /// Specifies which HTTP methods are permitted when accessing the resource from the allowed origins.
    /// </summary>
    public string[]? AllowedMethods { get; init; }

    /// <summary>
    /// Defines which HTTP headers can be used when making the actual request to the resource.
    /// </summary>
    public string[]? AllowedHeaders { get; init; }

    /// <summary>
    /// Indicates whether the resource supports credentials like cookies, authorization headers,
    /// or TLS client certificates.
    /// </summary>
    public bool? AllowCredentials { get; init; }

    /// <summary>
    /// Specifies which headers can be exposed as part of the response by listing them.
    /// </summary>
    public string[]? ExposeHeaders { get; init; }

    /// <summary>
    /// Defines the maximum duration the information provided by the Access-Control-Allow-Methods and
    /// Access-Control-Allow-Headers headers can be cached.
    /// </summary>
    public TimeSpan? MaxAge { get; init; }
}
