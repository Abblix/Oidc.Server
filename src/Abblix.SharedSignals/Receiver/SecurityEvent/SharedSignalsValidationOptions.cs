// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using Abblix.SecurityEvents.Validation;

namespace Abblix.SharedSignals.Receiver.SecurityEvent;

/// <summary>
/// The validation expectations of an SSF receiver: everything the core profile expects of a SET,
/// plus what the SSF profile adds - the stream the event must belong to and the transmitter's
/// declared critical subject members. The SSF steps refuse to run against the base options type,
/// so a profile wired with the wrong flavor fails loudly on its first token.
/// </summary>
public sealed record SharedSignalsValidationOptions : SecurityEventTokenValidationOptions
{
    /// <summary>
    /// The issuer of the stream the events arrive on, from its Stream Configuration. SSF 1.0
    /// Section 4.1.6 requires the "iss" claim to match both the Stream Configuration's issuer
    /// and the issuer the Transmitter Configuration was requested from; the receiver proved
    /// those two equal when it accepted the stream (Sections 7.2.2, 8.1.1.1), so one value here
    /// carries both halves of the rule.
    /// </summary>
    public string? StreamIssuer { get; init; }

    /// <summary>
    /// The complex-subject member names the transmitter declared critical
    /// ("critical_subject_members" in its configuration metadata, SSF 1.0 Section 7.1). An
    /// event whose subject carries one of them in a form this receiver cannot interpret is
    /// discarded (Section 3.6).
    /// </summary>
    public IReadOnlyCollection<string> CriticalSubjectMembers { get; init; } = [];

    /// <summary>
    /// The options the "sub_id" claim is read with. Null - the common case - reads the built-in
    /// vocabulary, which already spans the RFC 9493 registry and the SSF extensions; a
    /// deployment speaking proprietary formats supplies options carrying its own extended
    /// subject converter.
    /// </summary>
    public JsonSerializerOptions? SubjectSerializerOptions { get; init; }
}
