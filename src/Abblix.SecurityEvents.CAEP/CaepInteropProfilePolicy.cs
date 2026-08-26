// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// What the CAEP Interoperability Profile 1.0 demands of a TRANSMITTER's payload, on top of what CAEP 1.0
/// permits: each of the profile's three use cases requires <c>reason_admin</c> to carry a non-empty object.
/// </summary>
/// <remarks>
/// Section 3 opens "An implementation conforming to this profile MUST support at least one of the following
/// use cases", so there is no way to claim the profile without meeting this on some event. Section 3.1 says
/// "The reason_admin field of the event MUST be populated with a non-empty object"; Sections 3.2 and 3.3
/// name the actor outright, "Transmitters MUST populate this value with a non-empty object".
/// <para>
/// The obligation is the transmitter's alone. Nothing anywhere requires a receiver to reject an event
/// without the member, and CAEP 1.0 Section 3.1.1 positively requires an empty <c>session-revoked</c>
/// payload to be accepted - which is why <see cref="CaepEventPayload.ReasonAdmin"/> stays optional and this
/// lives beside the type rather than on it.
/// </para>
/// <para>
/// Registering it is how a deployment claims the profile. A host that does not is emitting CAEP 1.0 events,
/// which is a smaller claim and a valid one.
/// </para>
/// </remarks>
public sealed class CaepInteropProfilePolicy : IEventPayloadPolicy
{
    /// <inheritdoc />
    public string? RefusalOf(string eventType, IEventPayload? payload)
    {
        if (!RequiresReasonAdmin(eventType))
            return null;

        // Stated as what must be PRESENT, so every way of failing it - no payload, a payload of another
        // vocabulary, an absent member, an empty object - is refused by one condition rather than by a list
        // of absences that is always short by one. The empty object is the case a presence check misses:
        // "reason_admin": {} deserializes to a non-null empty dictionary and is emitted as written.
        return payload is CaepEventPayload { ReasonAdmin.Count: > 0 }
            ? null
            : $"The CAEP Interoperability Profile 1.0 requires a transmitter to populate '"
              + $"{CaepClaimNames.ReasonAdmin}' with a non-empty object on '{eventType}', and this event "
              + "carries none. Populate it, or do not register this policy if the deployment claims CAEP "
              + "1.0 rather than the interoperability profile.";
    }

    /// <summary>
    /// The three use cases of the profile's Section 3. CAEP 1.0 defines more event types, and the profile
    /// makes no demand of them, so they pass.
    /// </summary>
    private static bool RequiresReasonAdmin(string eventType) => eventType switch
    {
        CaepEventTypes.SessionRevoked => true,
        CaepEventTypes.CredentialChange => true,
        CaepEventTypes.DeviceComplianceChange => true,
        _ => false,
    };
}
