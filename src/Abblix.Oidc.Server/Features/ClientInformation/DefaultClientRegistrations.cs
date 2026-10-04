// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Features.ClientInformation;

/// <summary>
/// Chooses where the reloadable client store keeps registrations: in the host's store of registrations for the
/// tenants when one is registered, in memory otherwise.
/// </summary>
internal static class DefaultClientRegistrations
{
    /// <summary>
    /// The registrations the server serves from.
    /// </summary>
    /// <remarks>
    /// A store of registrations on a server without tenants is refused at startup by
    /// <see cref="TenantClientRegistrationStoreValidator"/>.
    /// </remarks>
    public static IClientRegistrations Create(IServiceProvider serviceProvider)
    {
#pragma warning disable ABXMT001
        return MultiTenancyDetection.IsActive(serviceProvider) &&
               serviceProvider.GetService<ITenantClientRegistrationStore>() is { } store
            ? new TenantStoreClientRegistrations(
                store,
                CurrentTenantOf(serviceProvider.GetRequiredService<ITenantAccessor>()))
            : ActivatorUtilities.CreateInstance<IssuerClientRegistrations>(serviceProvider);
#pragma warning restore ABXMT001
    }

#pragma warning disable ABXMT001
    private static Func<TenantDefinition> CurrentTenantOf(ITenantAccessor accessor)
        => () => TenantKey.CurrentTenant(accessor);
#pragma warning restore ABXMT001
}
