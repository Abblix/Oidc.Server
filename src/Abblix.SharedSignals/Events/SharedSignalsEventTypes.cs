// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;

namespace Abblix.SharedSignals.Events;

/// <summary>
/// The event type URIs of the events SSF 1.0 itself defines - the framework's own signals about
/// a stream, as opposed to the CAEP and RISC events that ride on it.
/// </summary>
public static class SharedSignalsEventTypes
{
#pragma warning disable S1075 // URIs should not be hardcoded - these are the specification-fixed event type identifiers, not configuration
    /// <summary>
    /// The Verification Event a receiver requests to confirm a stream is configured correctly,
    /// end to end (SSF 1.0 Section 8.1.4.1).
    /// </summary>
    public const string Verification = "https://schemas.openid.net/secevent/ssf/event-type/verification";

    /// <summary>
    /// The Stream Updated Event a transmitter must send when it changes a stream's status on its
    /// own - before stopping the stream on a pause or disable, and upon re-enabling it
    /// (SSF 1.0 Section 8.1.5).
    /// </summary>
    public const string StreamUpdated = "https://schemas.openid.net/secevent/ssf/event-type/stream-updated";
#pragma warning restore S1075

    /// <summary>
    /// Registers the two event types Shared Signals defines for itself, with their payload models.
    /// </summary>
    /// <remarks>
    /// Both roles call this, because both need it: the transmitter mints a verification and a
    /// stream-updated event, and the receiver is expected to act on them. Left unregistered they
    /// still validate and still reach a sink - as an untyped payload, so the branch a host wrote
    /// for them never matches and nothing anywhere says why. A receiver would simply wait on a
    /// stream it had been told was paused.
    /// <para>
    /// Registering the same type twice is an error the registry reports, and one host running both
    /// roles would do exactly that, so a mapping already in place is left alone. A DIFFERENT
    /// mapping under one of these names is not smoothed over: that is a host overriding a
    /// framework event, and it keeps the registry's own refusal.
    /// </para>
    /// </remarks>
    /// <param name="registry">The registry events deserialize through.</param>
    public static EventTypeRegistry RegisterSharedSignalsEvents(this EventTypeRegistry registry)
    {
        ArgumentNullException.ThrowIfNull(registry);

        Register<VerificationEventPayload>(registry, Verification);
        Register<StreamUpdatedEventPayload>(registry, StreamUpdated);

        return registry;

        static void Register<TPayload>(EventTypeRegistry registry, string eventType)
            where TPayload : IEventPayload
        {
            // The same mapping already in place is this call running twice - one host wiring both
            // roles. Anything else under one of these names is a host's own override, and the
            // registry's refusal is the right answer to that rather than a silent skip.
            if (!registry.TryGetPayloadType(eventType, out var registered) || registered != typeof(TPayload))
                registry.Register<TPayload>(eventType);
        }
    }
}
