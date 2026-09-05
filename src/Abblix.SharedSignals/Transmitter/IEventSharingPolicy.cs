// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The transmitter's own answer to SSF 1.0 Section 9.2: a subject added to a stream is a
/// statement of the receiver's INTEREST, never an entitlement, and the transmitter "SHOULD
/// validate that they are permitted to share the information contained within an event with
/// the Event Receiver before transmitting". The mechanism is deliberately outside the
/// specification's scope - and outside this package's: the host implements it over whatever
/// authorization model it has, and the dispatcher asks it about every otherwise-matching
/// delivery, last.
/// </summary>
public interface IEventSharingPolicy
{
    /// <summary>
    /// Decides whether the information in one event may be shared with one stream's receiver.
    /// </summary>
    /// <param name="stream">The stream the event would be delivered over.</param>
    /// <param name="descriptor">The event as the application stated it.</param>
    /// <param name="cancellationToken">Cancels I/O the decision performs.</param>
    /// <returns>True to let the delivery proceed; false to withhold it, silently - a receiver
    /// learns nothing from what does not arrive (SSF 1.0 Section 9.2).</returns>
    Task<bool> IsSharingPermittedAsync(
        StreamState stream,
        SecurityEventDescriptor descriptor,
        CancellationToken cancellationToken = default);
}
