// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SharedSignals.Model;

/// <summary>
/// The wire names of the Event Stream Management API members (SSF 1.0 Section 8.1). One registry
/// rather than one per model, because the same member crosses several bodies - "stream_id" appears
/// in the configuration, both status shapes, both subject requests and the verification request -
/// and per-model copies of one name drift apart.
/// </summary>
public static class StreamMemberNames
{
    /// <summary>The stream's unique identifier (SSF 1.0 Section 8.1.1).</summary>
    public const string StreamId = "stream_id";

    /// <summary>The transmitter's issuer identifier (SSF 1.0 Section 8.1.1).</summary>
    public const string Issuer = "iss";

    /// <summary>The audience identifying the stream's receiver(s) (SSF 1.0 Section 8.1.1).</summary>
    public const string Audience = "aud";

    /// <summary>The event types the transmitter supports for this receiver
    /// (SSF 1.0 Section 8.1.1).</summary>
    public const string EventsSupported = "events_supported";

    /// <summary>The event types the receiver asked for (SSF 1.0 Section 8.1.1).</summary>
    public const string EventsRequested = "events_requested";

    /// <summary>The event types the transmitter must include in the stream
    /// (SSF 1.0 Section 8.1.1).</summary>
    public const string EventsDelivered = "events_delivered";

    /// <summary>The delivery method object (SSF 1.0 Sections 8.1.1, 6.1).</summary>
    public const string Delivery = "delivery";

    /// <summary>The minimum number of seconds between verification requests
    /// (SSF 1.0 Section 8.1.1).</summary>
    public const string MinVerificationInterval = "min_verification_interval";

    /// <summary>The receiver's human-readable description of the stream
    /// (SSF 1.0 Section 8.1.1).</summary>
    public const string Description = "description";

    /// <summary>The stream's refreshable inactivity timeout in seconds
    /// (SSF 1.0 Section 8.1.1).</summary>
    public const string InactivityTimeout = "inactivity_timeout";

    /// <summary>The stream's status value (SSF 1.0 Section 8.1.2).</summary>
    public const string Status = "status";

    /// <summary>Why the stream's status is what it is (SSF 1.0 Section 8.1.2).</summary>
    public const string Reason = "reason";

    /// <summary>The subject a request adds or removes (SSF 1.0 Section 8.1.3).</summary>
    public const string Subject = "subject";

    /// <summary>Whether the receiver has verified the subject claim
    /// (SSF 1.0 Section 8.1.3.2).</summary>
    public const string Verified = "verified";

    /// <summary>The opaque value echoed back in the Verification Event
    /// (SSF 1.0 Section 8.1.4).</summary>
    public const string State = "state";
}
