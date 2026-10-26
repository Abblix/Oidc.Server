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
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Builds the stream stores of one tenant's transmitter over the tenant's part of the store every tenant shares.
/// </summary>
/// <param name="logger">Records a stream written after its tenant's release that could not be deleted.</param>
/// <param name="serviceProvider">Builds the store of declared streams and holds the store every tenant shares.</param>
internal sealed class TenantStreamStores(ILogger<TenantStreamStores> logger, IServiceProvider serviceProvider)
{
    /// <summary>
    /// The stores of <paramref name="tenant"/>'s transmitter: the one its own writes go to, the one the rest of the
    /// transmitter reads and writes, and whether the first was replaced by another transmitter's.
    /// </summary>
    /// <param name="tenant">The tenant whose streams these are.</param>
    /// <param name="released">Canceled once the tenant's creation is released.</param>
    /// <param name="identity">The issuer the declared streams name.</param>
    /// <param name="pollEndpoints">The poll address the declared streams name.</param>
    /// <param name="declared">The streams the tenant declares, or null for a tenant serving its part of the store
    /// alone.</param>
    public (IStreamStore Store, IStreamStore View, Func<bool> Superseded) Build(
        TenantDefinition tenant,
        CancellationToken released,
        ITransmitterIdentity identity,
        PollEndpointLocator pollEndpoints,
        TenantStreamDeclaration? declared)
    {
        var own = new ReleaseCheckingStreamStore(
            logger,
            new TenantStreamStore(
                serviceProvider.GetRequiredKeyedService<IStreamStore>(TenantTransmitters.SharedStoreKey),
                tenant),
            released,
            TenantKey.PartitionOf(tenant));

        if (declared is null)
            return (own, own, static () => false);

        var store = serviceProvider.CreateService<ConfigurationStreamStore>(
            Dependency.Override(declared.Streams),
            Dependency.Override<IStreamStore>(new SupersededWritesRefusedStreamStore(own, declared.IsInstalled)),
            Dependency.Override(identity),
            Dependency.Override(pollEndpoints));

        return (store, declared.Served, () => !declared.IsInstalled());
    }
}
