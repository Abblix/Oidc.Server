// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Serialization;
using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.RISC;

/// <summary>
/// Identifier Changed (RISC 1.0 Section 2.5): the identifier in the subject has changed. The
/// subject MUST be an email or phone_number subject carrying the OLD value, and only the
/// provider authoritative over the identifier should issue the event - a username change at a
/// non-authoritative provider is Recovery Information Changed (Section 2.10) instead.
/// </summary>
public sealed record IdentifierChangedPayload : IEventPayload
{
    /// <summary>
    /// OPTIONAL. The new value of the identifier (RISC 1.0 Section 2.5).
    /// </summary>
    [JsonPropertyName(RiscClaimNames.NewValue)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? NewValue { get; init; }
}
