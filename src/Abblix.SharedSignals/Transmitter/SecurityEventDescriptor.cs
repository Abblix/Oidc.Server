// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Subjects;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// One security event as the transmitter's application states it, before any stream is chosen:
/// what happened, to whom, and when. The dispatcher turns it into per-stream SETs - each stream
/// gets its own token with its own audience and identifier, per the one-receiver-per-SET
/// guidance of SSF 1.0 Section 4.1.8.
/// </summary>
public sealed record SecurityEventDescriptor
{
    /// <summary>
    /// The event type URI - the key the statement travels under in the "events" claim, and the
    /// value matched against the stream's delivered set.
    /// </summary>
    public required string EventType { get; init; }

    /// <summary>
    /// The subject the event is about, carried as the SET's top-level "sub_id"
    /// (SSF 1.0 Section 4.1.2) and matched against the stream's subjects
    /// (Section 8.1.3.1).
    /// </summary>
    public required SubjectIdentifier Subject { get; init; }

    /// <summary>
    /// The event's payload; null is an event whose statement is the empty JSON object
    /// (RFC 8417 Section 2).
    /// </summary>
    public IEventPayload? Payload { get; init; }

    /// <summary>
    /// The "txn" claim correlating this event with others of the same transaction; absent when
    /// there is no transaction to name (RFC 8417 Section 2.2).
    /// </summary>
    public string? TransactionId { get; init; }

    /// <summary>
    /// When the event itself occurred, as opposed to when its SETs are issued; absent when the
    /// transmitter declines to share an event time (RFC 8417 Section 2.2).
    /// </summary>
    public DateTimeOffset? TimeOfEvent { get; init; }
}
