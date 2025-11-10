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

using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Marker attribute that indicates a controller or action is enabled by a specific OIDC endpoint configuration.
/// Controllers or actions marked with this attribute will be removed from the application model if the specified
/// endpoint is not enabled in <see cref="OidcOptions.EnabledEndpoints"/>.
/// </summary>
/// <remarks>
/// This attribute is processed at application startup by <see cref="Conventions.EndpointControllerConvention"/>,
/// which removes controllers or actions from the application model if their endpoint is disabled. This prevents
/// the controller/action from being registered at all, rather than checking at runtime.
/// </remarks>
[AttributeUsage(AttributeTargets.Class | AttributeTargets.Method)]
public class EnabledByAttribute : Attribute
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EnabledByAttribute"/> class.
    /// </summary>
    /// <param name="endpoint">The OIDC endpoint configuration flag that controls whether this controller/action is enabled.</param>
    public EnabledByAttribute(OidcEndpoints endpoint)
    {
        Endpoint = endpoint;
    }

    /// <summary>
    /// The OIDC endpoint configuration flag.
    /// </summary>
    public OidcEndpoints Endpoint { get; }
}
