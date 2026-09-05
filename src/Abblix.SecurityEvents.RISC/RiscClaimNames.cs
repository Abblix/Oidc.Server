// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.RISC;

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
