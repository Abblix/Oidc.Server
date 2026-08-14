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
