// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Events;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Builds the events a transmitter sends about a stream itself (Factory). Each is about the stream,
/// so its subject is the stream's own: opaque, its id the stream's (SSF 1.0 Section 8.1.4.1).
/// </summary>
internal static class StreamEventDescriptors
{
    /// <summary>
    /// The Verification Event of SSF 1.0 Section 8.1.4, echoing the receiver's "state".
    /// </summary>
    /// <param name="streamId">The stream being verified.</param>
    /// <param name="state">What the receiver asked to have echoed, if anything.</param>
    public static SecurityEventDescriptor Verification(string streamId, string? state) => new()
    {
        EventType = SharedSignalsEventTypes.Verification,
        Subject = new OpaqueSubject(streamId),
        Payload = new VerificationEventPayload { State = state },
    };

    /// <summary>
    /// The Stream Updated Event of SSF 1.0 Section 8.1.5, announcing a status the transmitter set.
    /// </summary>
    /// <param name="streamId">The stream whose status changed.</param>
    /// <param name="status">The new status.</param>
    /// <param name="reason">Why the transmitter changed it.</param>
    public static SecurityEventDescriptor StreamUpdated(string streamId, string status, string? reason) => new()
    {
        EventType = SharedSignalsEventTypes.StreamUpdated,
        Subject = new OpaqueSubject(streamId),
        Payload = new StreamUpdatedEventPayload { Status = status, Reason = reason },
    };
}
