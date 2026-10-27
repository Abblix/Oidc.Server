// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Builds the transmitter of one tenant, every part bound to it, and the transmitter serving no tenant.
/// </summary>
/// <param name="serviceProvider">Builds the tenant's signer and holds the outbox and the lease every tenant shares.</param>
/// <param name="stores">Builds the tenant's stream stores.</param>
/// <param name="assembler">Puts the transmitter together.</param>
/// <param name="options">The transmitter's options.</param>
/// <param name="routes">Where the transmitter's routes were mapped.</param>
/// <param name="tenants">Names the tenant served when a part is used, which a tenant's parts refuse to serve another.</param>
internal sealed class TenantTransmitterBuilder(
    IServiceProvider serviceProvider,
    TenantStreamStores stores,
    TransmitterAssembler assembler,
    SharedSignalsTransmitterOptions options,
    TransmitterRoutes routes,
    ITenantAccessor tenants)
{
    /// <summary>
    /// The transmitter of <paramref name="tenant"/>, serving the streams it declares when <paramref name="declared"/>
    /// names them.
    /// </summary>
    /// <param name="tenant">The creation of the tenant whose stores the transmitter keeps.</param>
    /// <param name="current">The tenant's definition in force, which the transmitter answers and signs as.</param>
    /// <param name="released">Canceled once the tenant's creation is released.</param>
    /// <param name="declared">The streams the tenant declares, or null for a tenant serving its part of the store
    /// alone.</param>
    /// <exception cref="InvalidOperationException">
    /// The tenant declares a stream no request could be served from.</exception>
    public TenantTransmitter Build(
        TenantDefinition tenant,
        Func<TenantDefinition> current,
        CancellationToken released,
        TenantStreamDeclaration? declared)
    {
        var identity = new TenantTransmitterIdentity(current, options);
        var pollEndpoints = new PollEndpointLocator(options, routes, identity);
        var guard = new TenantPartGuard(tenants, tenant, released);

        return assembler.Assemble(
            identity,
            pollEndpoints,
            stores.Build(tenant, released, identity, pollEndpoints, declared, guard),
            new TenantEventOutbox(serviceProvider.GetRequiredService<IEventOutbox>(), tenant, guard),
            new InForceTenantTokenSigner(serviceProvider.CreateService<TenantSecurityEventTokenSigner>(), current, guard),
            new TenantDeliveryLease(serviceProvider.GetRequiredService<IDeliveryLease>(), tenant));
    }

    /// <summary>
    /// The transmitter resolved where no tenant is served: building it succeeds, so a request reaching no tenant is
    /// answered by the transmitter's own refusal, and each of its parts refuses once it reaches the streams, the outbox
    /// or the signing keys, all of which belong to a tenant.
    /// </summary>
    public TenantTransmitter BuildNone()
    {
        var identity = new NoTenantTransmitterIdentity(options);
        var none = new NoTenantStreamStore();

        return assembler.Assemble(
            identity,
            new PollEndpointLocator(options, routes, identity),
            (none, none, static () => false),
            new NoTenantEventOutbox(),
            new NoTenantTokenSigner(),
            serviceProvider.GetRequiredService<IDeliveryLease>());
    }
}
