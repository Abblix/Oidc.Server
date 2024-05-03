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
