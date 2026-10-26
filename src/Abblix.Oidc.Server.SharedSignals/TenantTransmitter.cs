// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Abstractions;
using Abblix.SharedSignals.Telemetry;
using Abblix.SharedSignals.Transmitter;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// The Shared Signals transmitter of one tenant: every part of it bound to that tenant's issuer, addresses, part of
/// the stores and signing keys when it is built, so nothing in it asks which tenant a request was resolved to.
/// </summary>
/// <remarks>
/// Built by <see cref="TenantTransmitters"/>, which keeps one per creation of a tenant and lets it go with that
/// creation.
/// </remarks>
internal sealed class TenantTransmitter
{
    /// <summary>The tenant's issuer and the addresses under it.</summary>
    public required ITransmitterIdentity Identity { get; init; }

    /// <summary>
    /// The tenant's streams, written through the transmitter the tenant is served when the write is made, so a write
    /// a superseded store of declared streams refuses is made again through the one that replaced it.
    /// </summary>
    public required IStreamStore Streams { get; init; }

    /// <summary>The store of this transmitter alone: the tenant's part of the shared store, or its declared streams.</summary>
    public required IStreamStore Store { get; init; }

    /// <summary>Whether a store of declared streams of another transmitter replaced this one's.</summary>
    public required Func<bool> Superseded { get; init; }

    /// <summary>Signs the tenant's security events with its own keys.</summary>
    public required ISecurityEventTokenSigner TokenSigner { get; init; }

    /// <summary>Signs a queued event for delivery.</summary>
    public required QueuedEventSigner Signer { get; init; }

    /// <summary>Records the tenant's events and deliveries under its id.</summary>
    public required SharedSignalsInstruments Instruments { get; init; }

    /// <summary>Where the tenant's streams are polled.</summary>
    public required PollEndpointLocator PollEndpoints { get; init; }

    /// <summary>Where the tenant's management API is served.</summary>
    public required ManagementEndpointLocator ManagementEndpoints { get; init; }

    /// <summary>Fans an event of the tenant out to its streams.</summary>
    public required EventDispatcher Dispatcher { get; init; }

    /// <summary>The tenant's Stream Management API.</summary>
    public required StreamManagementService Management { get; init; }

    /// <summary>Answers the tenant's receivers polling their streams.</summary>
    public required PollEndpointHandler PollHandler { get; init; }

    /// <summary>Delivers the tenant's queued events to the receivers that take them by push.</summary>
    public required PushDeliverySweep Sweep { get; init; }
}
