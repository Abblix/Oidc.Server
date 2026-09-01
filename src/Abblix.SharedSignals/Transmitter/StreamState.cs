// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Everything the transmitter holds about one stream: the configuration document the receiver
/// sees (SSF 1.0 Section 8.1.1), the status (Section 8.1.2), and the subject bookkeeping the
/// receiver drives through the subject endpoints (Section 8.1.3). An immutable snapshot - the
/// store replaces whole states, so a half-applied update is unrepresentable.
/// </summary>
/// <remarks>
/// The JSON member names are pinned rather than left to the property names, because a durable
/// <see cref="IStreamStore"/> persists this type: without them a C# rename - a refactor with no
/// wire consequence anywhere else - either breaks reading every stored registration or, for the
/// optional members, silently resets it, so a stream a receiver had paused would come back
/// enabled. The names are storage, not protocol: the document a receiver reads back is
/// <see cref="Configuration"/>, which carries its own.
/// </remarks>
public sealed record StreamState
{
    /// <summary>
    /// The identity of the receiver the stream belongs to, as the host's authentication
    /// established it. The transmitter may serve every receiver from the same endpoints and
    /// tell them apart by credentials (SSF 1.0 Section 8.1) - this is where that identity
    /// lands, and every management operation is scoped by it.
    /// </summary>
    [JsonPropertyName("receiver_id")]
    public required string ReceiverId { get; init; }

    /// <summary>
    /// The stream's configuration document, exactly as the receiver reads it back.
    /// </summary>
    [JsonPropertyName("configuration")]
    public required StreamConfiguration Configuration { get; init; }

    /// <summary>
    /// The stream's status value, one of <see cref="StreamStatuses"/>. A stream starts enabled:
    /// creating one is the receiver asking for events, and a default that needed a second call
    /// to start the flow would read as a broken stream.
    /// </summary>
    [JsonPropertyName("status")]
    public string Status { get; init; } = StreamStatuses.Enabled;

    /// <summary>
    /// Why the status is what it is, when anyone said (SSF 1.0 Section 8.1.2).
    /// </summary>
    [JsonPropertyName("status_reason")]
    public string? StatusReason { get; init; }

    /// <summary>
    /// Which subjects the stream covers by default, fixed at creation from the transmitter's
    /// advertisement (SSF 1.0 Section 7.1).
    /// </summary>
    [JsonPropertyName("subjects_mode")]
    public required StreamSubjectsMode SubjectsMode { get; init; }

    /// <summary>
    /// The subjects the receiver added (SSF 1.0 Section 8.1.3.2). Under
    /// <see cref="StreamSubjectsMode.None"/> these are the coverage; under
    /// <see cref="StreamSubjectsMode.All"/> they undo earlier removals.
    /// </summary>
    [JsonPropertyName("added_subjects")]
    public IReadOnlyList<StreamSubject> AddedSubjects { get; init; } = [];

    /// <summary>
    /// The subjects the receiver removed (SSF 1.0 Section 8.1.3.3) - meaningful under
    /// <see cref="StreamSubjectsMode.All"/>, where they carve subjects out of the default
    /// coverage.
    /// </summary>
    [JsonPropertyName("removed_subjects")]
    public IReadOnlyList<SubjectIdentifier> RemovedSubjects { get; init; } = [];

    /// <summary>
    /// When the receiver last triggered a verification event, the fact the
    /// "min_verification_interval" throttle is measured against (SSF 1.0 Sections 8.1.1,
    /// 8.1.4.2); null before the first trigger.
    /// </summary>
    [JsonPropertyName("last_verification_request_at")]
    public DateTimeOffset? LastVerificationRequestAt { get; init; }

    /// <summary>
    /// What the store's copy looked like when this one was read, so a write can tell whether
    /// anything happened in between.
    /// </summary>
    /// <remarks>
    /// Every mutation of a stream is a read, a change in memory and a write back, and without this
    /// the write is unconditional: two calls adding a subject at once both read the same list, both
    /// write, both are answered 200, and one addition is gone. SSF 1.0 Section 9.1 tells a receiver
    /// that a success says nothing about what the transmitter did, so it never retries and never
    /// learns.
    /// <para>
    /// Opaque, and the store's to mint: a caller passes back what it was given, and
    /// <see cref="IStreamStore.UpdateAsync"/> refuses a write carrying anything else. Null belongs
    /// to a state that was built rather than read, which is why creation has its own method.
    /// </para>
    /// </remarks>
    [JsonPropertyName("version")]
    public string? Version { get; init; }

    /// <summary>
    /// The stream's identifier, read off the configuration - one value, one owner.
    /// </summary>
    [JsonIgnore]
    public string StreamId => Configuration.StreamId;
}
