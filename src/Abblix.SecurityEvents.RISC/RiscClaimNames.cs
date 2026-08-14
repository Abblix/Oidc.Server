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

namespace Abblix.SecurityEvents.Risc;

/// <summary>
/// The wire names of the event-specific claims RISC 1.0 defines, spelled exactly as the
/// specification spells them - including the one hyphenated outlier.
/// </summary>
public static class RiscClaimNames
{
    /// <summary>Why the account was disabled (RISC 1.0 Section 2.3).</summary>
    public const string Reason = "reason";

    /// <summary>
    /// The new value of a changed identifier (RISC 1.0 Section 2.5). The specification spells
    /// this one with a hyphen, unlike every underscore-separated claim around it.
    /// </summary>
    public const string NewValue = "new-value";

    /// <summary>The type of the compromised credential (RISC 1.0 Section 2.7).</summary>
    public const string CredentialType = "credential_type";

    /// <summary>When the transmitter discovered the compromise (RISC 1.0 Section 2.7).</summary>
    public const string EventTimestamp = "event_timestamp";

    /// <summary>The reason intended for administrators (RISC 1.0 Section 2.7).</summary>
    public const string ReasonAdmin = "reason_admin";

    /// <summary>The reason intended for end users (RISC 1.0 Section 2.7).</summary>
    public const string ReasonUser = "reason_user";
}
