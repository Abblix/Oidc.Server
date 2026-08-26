// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.CAEP;

/// <summary>
/// What the CAEP Interoperability Profile 1.0 demands of a TRANSMITTER's payload, on top of what CAEP 1.0
/// permits: each of its three use cases requires <c>reason_admin</c> to carry a non-empty object.
/// </summary>
/// <remarks>
/// Section 3.1 says "The reason_admin field of the event MUST be populated with a non-empty object";
/// Sections 3.2 and 3.3 name the actor outright, "Transmitters MUST populate this value with a non-empty
/// object". The obligation is the transmitter's alone - neither document asks a receiver to reject an
/// event without it.
/// <para>
/// CAEP 1.0 leaves the member optional - Section 2, "The following claims are optional unless otherwise
/// specified in the event definition" - and defines no event-specific claim for <c>session-revoked</c>
/// (Section 3.1.1), so an empty payload is well-formed under the base specification and the property stays
/// nullable. What CAEP 1.0 does say about the member once it appears is "The object MUST contain one or
/// more key/value pairs", so an EMPTY object is outside the base specification too and this policy is not
/// the only thing that would be wrong to emit it.
/// </para>
/// <para>
/// Registering it is how a deployment claims the profile. A host that does not is emitting CAEP 1.0
/// events, which is a smaller claim and a valid one.
/// </para>
/// </remarks>
/// <param name="claimedUseCases">
/// The use cases this deployment claims, by event type; empty claims all three. The profile's Section 1
/// says "Support for all use cases listed herein is not required in order to be considered compliant with
/// this profile. An implementation can choose specific use cases to support", so a deployment conforming
/// through one of them may still emit the others as plain CAEP 1.0 events. Naming the claimed ones is how
/// it keeps that freedom, and the default is deliberately the strict reading: a transmitter that has not
/// thought about it is better refused than quietly non-conformant.
/// </param>
public sealed class CaepInteropProfilePolicy(params string[] claimedUseCases) : IEventPayloadPolicy
{
    /// <summary>The event types the profile's Section 3 defines use cases for, and the only claimable
    /// values.</summary>
    private static readonly string[] UseCases =
    [
        CaepEventTypes.SessionRevoked,
        CaepEventTypes.CredentialChange,
        CaepEventTypes.DeviceComplianceChange,
    ];

    private readonly HashSet<string> _claimed = Claimed(claimedUseCases);

    /// <summary>
    /// The claimed set, refusing at construction anything the profile does not define.
    /// </summary>
    /// <remarks>
    /// An unrecognised value would otherwise leave a policy that is registered, resolvable, consulted on
    /// every event and refuses nothing - which is the state this class exists to prevent, reached by a
    /// typo or by the profile's own prose, where the use cases are named <c>session-revoked</c> rather
    /// than by their event type URI. Silence in the permissive direction is the one failure a deployment
    /// cannot notice, so it is answered at startup, where an issuer is answered two files away.
    /// </remarks>
    private static HashSet<string> Claimed(string[] claimedUseCases)
    {
        if (claimedUseCases is not { Length: > 0 })
            return [.. UseCases];

        // By INDEX, because the offending element can itself be null - a JSON array carrying a null, or
        // a missing configuration key read straight into the array - and a search returning the element
        // has no way to tell "found a null" from "found nothing". That sentinel collision is what let a
        // null through the first version of this guard, taking any real typo behind it along.
        var unknown = Array.FindIndex(
            claimedUseCases,
            claimed => !UseCases.Contains(claimed, StringComparer.Ordinal));

        if (unknown >= 0)
        {
            throw new ArgumentException(
                $"'{claimedUseCases[unknown] ?? "<null>"}' is not a use case of the CAEP Interoperability "
                + $"Profile 1.0. Its Section 3 defines three, by event type: {string.Join(", ", UseCases)}.",
                nameof(claimedUseCases));
        }

        return [.. claimedUseCases];
    }

    /// <summary>
    /// Claims all three use cases.
    /// </summary>
    /// <remarks>
    /// Spelled out rather than left to the parameter's default, because a container cannot satisfy a
    /// <c>params</c> array: without this, the natural registration
    /// <c>AddSingleton&lt;IEventPayloadPolicy, CaepInteropProfilePolicy&gt;()</c> compiles and then fails
    /// when the policy is first resolved.
    /// </remarks>
    public CaepInteropProfilePolicy()
        : this([])
    {
    }

    /// <inheritdoc />
    public string? RefusalOf(string eventType, IEventPayload? payload)
    {
        if (!_claimed.Contains(eventType))
            return null;

        return PopulatedReasonAdmin(payload) switch
        {
            true => null,

            // Stated as what the member is NOT, rather than as a guess at which way it failed. Absent, an
            // empty object, and a string where an object belongs are one verdict here, and enumerating
            // them would send a host debugging a relay to grep upstream for a member that is right there.
            false => $"'{CaepClaimNames.ReasonAdmin}' is not a non-empty object on '{eventType}'. The CAEP "
                + "Interoperability Profile 1.0 Section 3 requires a transmitter to populate it with a "
                + "non-empty object on every use case it claims, and CAEP 1.0 Section 2 requires the "
                + "object to carry one or more key/value pairs wherever it appears at all.",

            // The honest third answer, and it earns a message of its own: refusing a payload with "it
            // carries none" would be a statement about contents this policy never read.
            null => $"A payload of type '{payload?.GetType().Name}' cannot be read for "
                + $"'{CaepClaimNames.ReasonAdmin}', so this transmitter cannot show that '{eventType}' "
                + "meets the CAEP Interoperability Profile 1.0. Build the event with the payload types "
                + "this package defines, or supply a policy that understands this one.",
        };
    }

    /// <summary>
    /// Whether the payload carries a populated <c>reason_admin</c>, or null when this policy cannot tell.
    /// </summary>
    /// <remarks>
    /// Stated as what must be PRESENT, so no payload, an absent member and an empty object are all refused
    /// by one condition rather than by a list of absences that is always short by one. The empty object is
    /// the case a presence check misses: <c>"reason_admin": {}</c> deserializes to a non-null dictionary
    /// and is emitted as written.
    /// <para>
    /// The question is about the WIRE member rather than about a .NET type, which is why the relayed shape
    /// is read too: an event that arrived as raw JSON and is re-dispatched is conformant whenever its own
    /// <c>reason_admin</c> is populated, and judging it by its C# class would refuse it while asserting
    /// something about contents nobody looked at.
    /// </para>
    /// </remarks>
    private static bool? PopulatedReasonAdmin(IEventPayload? payload) => payload switch
    {
        null => false,
        CaepEventPayload caep => caep.ReasonAdmin is { Count: > 0 },
        UnknownEventPayload { Json: var json } =>
            json[CaepClaimNames.ReasonAdmin] is JsonObject { Count: > 0 },
        _ => null,
    };
}
