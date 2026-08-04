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

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SecurityEvents.Subjects;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// The subject matching of SSF 1.0 Section 8.1.3.1: the rule by which a transmitter decides
/// whether an event's subject falls under a subject the receiver added to its stream. Simple
/// subjects match when exactly identical; complex subjects match when EVERY field is undefined
/// on either side or identical on both - which is what makes an absent field a wildcard, so a
/// receiver adding just a tenant hears about every user of that tenant, and one adding user
/// plus device still hears an event that names only the user.
/// </summary>
public static class SubjectMatcher
{
    /// <summary>
    /// Decides whether two subjects match under Section 8.1.3.1. The relation is symmetric:
    /// the section's rules read the same whichever side the receiver's subject is on.
    /// </summary>
    /// <param name="first">One subject - conventionally the one added to the stream.</param>
    /// <param name="second">The other - conventionally the event's subject.</param>
    public static bool Matches(SubjectIdentifier first, SubjectIdentifier second)
    {
        ArgumentNullException.ThrowIfNull(first);
        ArgumentNullException.ThrowIfNull(second);

        // Two complex subjects match field-wise; every other pairing - simple against simple,
        // or simple against complex - falls to "exactly identical", which a format difference
        // fails by construction.
        return first is ComplexSubject firstComplex && second is ComplexSubject secondComplex
            ? FieldsMatch(firstComplex, secondComplex)
            : Identical(first, second);
    }

    private static bool FieldsMatch(ComplexSubject first, ComplexSubject second)
        => MemberMatches(first.User, second.User)
           && MemberMatches(first.Device, second.Device)
           && MemberMatches(first.Session, second.Session)
           && MemberMatches(first.Application, second.Application)
           && MemberMatches(first.Tenant, second.Tenant)
           && MemberMatches(first.OrgUnit, second.OrgUnit)
           && MemberMatches(first.Group, second.Group)
           && AdditionalMembersMatch(first.AdditionalMembers, second.AdditionalMembers);

    private static bool MemberMatches(SubjectIdentifier? first, SubjectIdentifier? second)
        => first is null || second is null || Identical(first, second);

    /// <summary>
    /// The same per-field rule over the members beyond the registered seven: Section 8.1.3.1
    /// ranges over "all fields in the Complex Subject", and the extension bag is where the
    /// fields this package does not interpret live.
    /// </summary>
    private static bool AdditionalMembersMatch(
        IDictionary<string, JsonElement>? first,
        IDictionary<string, JsonElement>? second)
    {
        if (first is not { Count: > 0 } || second is not { Count: > 0 })
        {
            return true;
        }

        foreach (var (name, firstValue) in first)
        {
            if (second.TryGetValue(name, out var secondValue)
                && !JsonNode.DeepEquals(
                    JsonSerializer.SerializeToNode(firstValue),
                    JsonSerializer.SerializeToNode(secondValue)))
            {
                return false;
            }
        }

        return true;
    }

    /// <summary>
    /// "Exactly identical" (SSF 1.0 Section 8.1.3.1), taken at the wire level: two subjects are
    /// identical when they serialize to equal JSON. The serialized form is what both parties
    /// actually exchanged, and each subtype writes its members in one fixed order, so the
    /// comparison is deterministic without a per-format equality to maintain. Public beside
    /// <see cref="Matches"/> because subject BOOKKEEPING wants the strict relation: a removal
    /// undoes exactly what was added, where the wildcard matching would over-reach.
    /// </summary>
    public static bool Identical(SubjectIdentifier first, SubjectIdentifier second)
        => JsonNode.DeepEquals(
            JsonSerializer.SerializeToNode<SubjectIdentifier>(first),
            JsonSerializer.SerializeToNode<SubjectIdentifier>(second));
}
