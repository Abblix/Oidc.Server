// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;

namespace Abblix.SharedSignals.Model;

/// <summary>
/// The body of a receiver's request that a Verification Event be sent over an Event Stream
/// (SSF 1.0 Section 8.1.4.2). Success is an empty 204, and it promises only that the event has
/// been or will be transmitted - possibly asynchronously, in no particular order relative to the
/// queue - so a receiver must not wait on it synchronously.
/// </summary>
public sealed record VerificationRequest
{
    /// <summary>
    /// REQUIRED. The stream the Verification Event is requested on (SSF 1.0 Section 8.1.4.2).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.StreamId)]
    public required string StreamId { get; init; }

    /// <summary>
    /// OPTIONAL. An arbitrary string the transmitter must echo back in the Verification Event's
    /// payload, letting the receiver correlate the event with this request; a
    /// transmitter-initiated Verification Event carries none (SSF 1.0 Section 8.1.4.2).
    /// </summary>
    [JsonPropertyName(StreamMemberNames.State)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? State { get; init; }
}
