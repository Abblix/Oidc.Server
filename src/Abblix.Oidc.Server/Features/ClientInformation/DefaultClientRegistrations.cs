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
    public static IClientRegistrations Create(IServiceProvider serviceProvider)
        => serviceProvider.GetService<ITenantClientRegistrationStore>() is { } store
            ? new TenantStoreClientRegistrations(store)
            : ActivatorUtilities.CreateInstance<IssuerClientRegistrations>(serviceProvider);
}
