// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// The transmitter of a tenant is ready once the server's tenant catalog has loaded its tenants: until then a request
/// reaches no tenant and would be answered by the transmitter of none.
/// </summary>
/// <remarks>
/// On a server that resolves its tenants, resolution has already waited for the load, so this completes at once.
/// </remarks>
/// <param name="catalog">The server's own tenant catalog.</param>
internal sealed class TenantLoadReadiness(StoreTenantCatalog catalog) : ITransmitterReadiness
{
    /// <summary>Registers it as the transmitter's readiness, unless the host registered one of its own.</summary>
    /// <param name="services">The service collection.</param>
    public static void Register(IServiceCollection services)
        => services.TryAddSingleton<ITransmitterReadiness, TenantLoadReadiness>();

    /// <inheritdoc />
    public ValueTask WaitAsync(CancellationToken cancellationToken) => catalog.LoadedAsync(cancellationToken);
}
