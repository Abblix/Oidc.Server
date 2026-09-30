// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using System.Reflection;
using Abblix.Oidc.Server.Common.Configuration;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// The settings a tenant declares that <see cref="OidcOptions"/> carries for a server without tenants: the same
/// name, and a type the server's setting can hold.
/// </summary>
/// <remarks>
/// Startup finds a tenant's settings here twice: to refuse the server-wide value of each, and to copy the tenant's
/// into the settings the server's own checks judge for that tenant.
/// </remarks>
[Experimental(MultiTenancyDiagnostics.Experimental)]
internal static class TenantOwnedSettings
{
    /// <summary>
    /// Each such setting, as the tenant's property and the server's.
    /// </summary>
    public static readonly (PropertyInfo Tenant, PropertyInfo Server)[] All = (
        from tenantProperty in typeof(TenantDefinition).GetProperties(BindingFlags.Public | BindingFlags.Instance)
        let serverProperty = typeof(OidcOptions).GetProperty(tenantProperty.Name)
        where serverProperty is { CanWrite: true } &&
              serverProperty.PropertyType.IsAssignableFrom(tenantProperty.PropertyType)
        select (tenantProperty, serverProperty)
    ).ToArray();
}
