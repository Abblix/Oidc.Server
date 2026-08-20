// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Marker attribute that indicates a controller or action is enabled by a specific OIDC endpoint configuration.
/// Controllers or actions marked with this attribute will be removed from the application model if the specified
/// endpoint is not enabled in <see cref="OidcOptions.EnabledEndpoints"/>.
/// </summary>
/// <remarks>
/// This attribute is processed at application startup by <see cref="Conventions.EnabledByConvention"/>,
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
