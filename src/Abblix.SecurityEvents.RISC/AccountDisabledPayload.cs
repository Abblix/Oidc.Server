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
