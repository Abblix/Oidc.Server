// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.MultiTenancy;

/// <summary>
/// Tells whether the server serves tenants, for the checks of the server's own settings that a tenant's settings
/// replace: under multi-tenancy those are judged per tenant, by the checks of the tenant list.
/// </summary>
internal static class MultiTenancyDetection
{
    /// <summary>
    /// Whether the check of the tenant list, which only multi-tenancy registers, is registered - asked of the
    /// container without building anything. A container that cannot say is taken for one without tenants.
    /// </summary>
    public static bool IsActive(IServiceProvider serviceProvider)
        => serviceProvider.GetService<IServiceProviderIsService>() is { } services &&
#pragma warning disable ABXMT001
           services.IsService(typeof(IValidateOptions<MultiTenancyOptions>));
#pragma warning restore ABXMT001
}
