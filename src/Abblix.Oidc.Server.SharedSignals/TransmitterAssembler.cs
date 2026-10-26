// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SharedSignals.Telemetry;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Puts a transmitter together from the parts that tell one tenant's from another's: what it answers as, the streams,
/// the outbox, the signer and the delivery lease.
/// </summary>
/// <remarks>
/// Each of those parts is handed to every part that uses it, rather than left for the container to resolve: what the
/// container holds is shared by every tenant, so a part it resolved would serve them all alike. The parts that are the
/// same for every tenant, the options, the clock, the policies of the host, come from the container.
/// </remarks>
/// <param name="serviceProvider">Builds the parts and holds the parts every tenant shares.</param>
/// <param name="options">The transmitter's options.</param>
/// <param name="routes">Where the transmitter's routes were mapped.</param>
/// <param name="httpClients">Makes the client push deliveries are posted through.</param>
internal sealed class TransmitterAssembler(
    IServiceProvider serviceProvider,
    SharedSignalsTransmitterOptions options,
    TransmitterRoutes routes,
    IHttpClientFactory httpClients)
{
    /// <summary>
    /// The transmitter whose parts answer as <paramref name="identity"/> over the streams, the outbox, the signer and
    /// the lease given.
    /// </summary>
    /// <param name="identity">What the transmitter answers as.</param>
    /// <param name="pollEndpoints">Where the transmitter's receivers poll, as its streams name it.</param>
    /// <param name="streams">The store the transmitter's own writes go to, the one the rest of it reads and writes,
    /// and whether the first was replaced by another transmitter's.</param>
    /// <param name="outbox">Where the transmitter queues its events.</param>
    /// <param name="tokenSigner">Signs the transmitter's events.</param>
    /// <param name="lease">Claims each stream for one push delivery at a time.</param>
    public TenantTransmitter Assemble(
        ITransmitterIdentity identity,
        PollEndpointLocator pollEndpoints,
        (IStreamStore Store, IStreamStore View, Func<bool> Superseded) streams,
        IEventOutbox outbox,
        ISecurityEventTokenSigner tokenSigner,
        IDeliveryLease lease)
    {
        var (store, view, superseded) = streams;
        var signer = serviceProvider.CreateService<QueuedEventSigner>(Dependency.Override(tokenSigner));
        var instruments = serviceProvider.CreateService<SharedSignalsInstruments>(Dependency.Override(identity));

        var dispatcher = serviceProvider.CreateService<EventDispatcher>(
            Dependency.Override(view),
            Dependency.Override(outbox),
            Dependency.Override(identity),
            Dependency.Override(instruments));

        return new TenantTransmitter
        {
            Identity = identity,
            Streams = view,
            Store = store,
            Superseded = superseded,
            TokenSigner = tokenSigner,
            Signer = signer,
            Instruments = instruments,
            PollEndpoints = pollEndpoints,
            ManagementEndpoints = new ManagementEndpointLocator(options, routes, identity),
            Dispatcher = dispatcher,
            Management = serviceProvider.CreateService<StreamManagementService>(
                Dependency.Override(view),
                Dependency.Override(outbox),
                Dependency.Override(dispatcher),
                Dependency.Override(pollEndpoints)),
            PollHandler = serviceProvider.CreateService<PollEndpointHandler>(
                Dependency.Override(outbox),
                Dependency.Override(signer)),
            Sweep = serviceProvider.CreateService<PushDeliverySweep>(
                Dependency.Override(view),
                Dependency.Override(Sender(outbox, instruments, signer)),
                Dependency.Override(lease)),
        };
    }

    /// <summary>
    /// Posts queued events to their receivers, through the client the transmitter registration set up, which refuses
    /// an address the receiver policy does not allow.
    /// </summary>
    private PushDeliverySender Sender(IEventOutbox outbox, SharedSignalsInstruments instruments, QueuedEventSigner signer)
        => serviceProvider.CreateService<PushDeliverySender>(
            Dependency.Override(httpClients.CreateClient(nameof(PushDeliverySender))),
            Dependency.Override(outbox),
            Dependency.Override(instruments),
            Dependency.Override(signer));
}
