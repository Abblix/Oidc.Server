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
/// Account Disabled (RISC 1.0 Section 2.3): the account identified by the subject has been
/// disabled and may be enabled again in the future - the reversible counterpart of
/// <see cref="AccountPurgedPayload"/>.
/// </summary>
public sealed record AccountDisabledPayload : IEventPayload
{
    /// <summary>
    /// The reasons Section 2.3 names. The claim is a free string, so the set is open to values
    /// the two parties agree on beyond these.
    /// </summary>
    public static class Reasons
    {
        /// <summary>The account was disabled because it was hijacked.</summary>
        public const string Hijacking = "hijacking";

        /// <summary>The account was disabled as part of bulk-created abusive accounts.</summary>
        public const string BulkAccount = "bulk-account";
    }

    /// <summary>
    /// OPTIONAL. Why the account was disabled, one of <see cref="Reasons"/>
    /// (RISC 1.0 Section 2.3).
    /// </summary>
    [JsonPropertyName(RiscClaimNames.Reason)]
    [JsonIgnore(Condition = JsonIgnoreCondition.WhenWritingNull)]
    public string? Reason { get; init; }
}
