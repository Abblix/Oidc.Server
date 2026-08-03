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

using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Model;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Everything the transmitter holds about one stream: the configuration document the receiver
/// sees (SSF 1.0 Section 8.1.1), the status (Section 8.1.2), and the subject bookkeeping the
/// receiver drives through the subject endpoints (Section 8.1.3). An immutable snapshot - the
/// store replaces whole states, so a half-applied update is unrepresentable.
/// </summary>
public sealed record StreamState
{
    /// <summary>
    /// The identity of the receiver the stream belongs to, as the host's authentication
    /// established it. The transmitter may serve every receiver from the same endpoints and
    /// tell them apart by credentials (SSF 1.0 Section 8.1) - this is where that identity
    /// lands, and every management operation is scoped by it.
    /// </summary>
    public required string ReceiverId { get; init; }

    /// <summary>
    /// The stream's configuration document, exactly as the receiver reads it back.
    /// </summary>
    public required StreamConfiguration Configuration { get; init; }

    /// <summary>
    /// The stream's status value, one of <see cref="StreamStatuses"/>. A stream starts enabled:
    /// creating one is the receiver asking for events, and a default that needed a second call
    /// to start the flow would read as a broken stream.
    /// </summary>
    public string Status { get; init; } = StreamStatuses.Enabled;

    /// <summary>
    /// Why the status is what it is, when anyone said (SSF 1.0 Section 8.1.2).
    /// </summary>
    public string? StatusReason { get; init; }

    /// <summary>
    /// Which subjects the stream covers by default, fixed at creation from the transmitter's
    /// advertisement (SSF 1.0 Section 7.1).
    /// </summary>
    public required StreamSubjectsMode SubjectsMode { get; init; }

    /// <summary>
    /// The subjects the receiver added (SSF 1.0 Section 8.1.3.2). Under
    /// <see cref="StreamSubjectsMode.None"/> these are the coverage; under
    /// <see cref="StreamSubjectsMode.All"/> they undo earlier removals.
    /// </summary>
    public IReadOnlyList<StreamSubject> AddedSubjects { get; init; } = [];

    /// <summary>
    /// The subjects the receiver removed (SSF 1.0 Section 8.1.3.3) - meaningful under
    /// <see cref="StreamSubjectsMode.All"/>, where they carve subjects out of the default
    /// coverage.
    /// </summary>
    public IReadOnlyList<SubjectIdentifier> RemovedSubjects { get; init; } = [];

    /// <summary>
    /// When the receiver last triggered a verification event, the fact the
    /// "min_verification_interval" throttle is measured against (SSF 1.0 Sections 8.1.1,
    /// 8.1.4.2); null before the first trigger.
    /// </summary>
    public DateTimeOffset? LastVerificationRequestAt { get; init; }

    /// <summary>
    /// The stream's identifier, read off the configuration - one value, one owner.
    /// </summary>
    public string StreamId => Configuration.StreamId;
}
