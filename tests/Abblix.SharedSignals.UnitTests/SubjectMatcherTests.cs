// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using Abblix.SecurityEvents.Subjects;
using Abblix.SharedSignals.Transmitter;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the subject matching of SSF 1.0 Section 8.1.3.1 against the section's own three
/// examples, plus the boundaries the examples leave implicit.
/// </summary>
public class SubjectMatcherTests
{
    [Fact]
    public void LessRestrictiveAddedSubject_MatchesTheEventsFullerSubject()
    {
        // The section's first example: the receiver added only the tenant; the event names the
        // tenant and a user. The user field is undefined on the added side - a wildcard.
        var added = new ComplexSubject
        {
            Tenant = new OpaqueSubject("example-a38h4792-uw2"),
        };
        var eventSubject = new ComplexSubject
        {
            Tenant = new OpaqueSubject("example-a38h4792-uw2"),
            User = new EmailSubject("jdoe@example.com"),
        };

        Assert.True(SubjectMatcher.Matches(added, eventSubject));
    }

    [Fact]
    public void MoreRestrictiveAddedSubject_StillMatchesAnEventNamingFewerFields()
    {
        // The section's second example: the receiver added user plus device; the event names
        // only the user. The device field is undefined on the event's side - the wildcard cuts
        // both ways.
        var added = new ComplexSubject
        {
            User = new EmailSubject("jdoe@example.com"),
            Device = new IpAddressesSubject("10.29.37.75"),
        };
        var eventSubject = new ComplexSubject
        {
            User = new EmailSubject("jdoe@example.com"),
        };

        Assert.True(SubjectMatcher.Matches(added, eventSubject));
    }

    [Fact]
    public void FieldDefinedOnBothSides_MustBeIdentical()
    {
        // The section's third example: both sides define the group, and the groups differ - no
        // match, however well the user agrees.
        var added = new ComplexSubject
        {
            User = new EmailSubject("jdoe@example.com"),
            Group = new DidSubject("did:example:123456"),
        };
        var eventSubject = new ComplexSubject
        {
            User = new EmailSubject("jdoe@example.com"),
            Group = new DidSubject("did:example:9999999"),
        };

        Assert.False(SubjectMatcher.Matches(added, eventSubject));
    }

    [Fact]
    public void SimpleSubjects_MatchOnlyWhenExactlyIdentical()
    {
        Assert.True(SubjectMatcher.Matches(
            new EmailSubject("jdoe@example.com"), new EmailSubject("jdoe@example.com")));
        Assert.False(SubjectMatcher.Matches(
            new EmailSubject("jdoe@example.com"), new EmailSubject("other@example.com")));

        // Same identifying value under different formats is not "exactly identical".
        Assert.False(SubjectMatcher.Matches(
            new OpaqueSubject("jdoe@example.com"), new EmailSubject("jdoe@example.com")));
    }

    [Fact]
    public void SimpleAgainstComplex_IsNotAMatch()
    {
        // Section 8.1.3.1 defines simple-simple and complex-complex; a pairing across the two
        // falls to "exactly identical", which the format difference fails.
        Assert.False(SubjectMatcher.Matches(
            new EmailSubject("jdoe@example.com"),
            new ComplexSubject { User = new EmailSubject("jdoe@example.com") }));
    }

    [Fact]
    public void AdditionalMembers_FollowTheSamePerFieldRule()
    {
        // "all fields in the Complex Subject" ranges over extension members too: one side not
        // defining the field is a wildcard, both defining it demands identity.
        var withWorkload = new ComplexSubject
        {
            User = new EmailSubject("jdoe@example.com"),
            AdditionalMembers = new Dictionary<string, JsonElement>
            {
                ["workload"] = JsonSerializer.SerializeToElement(new { format = "opaque", id = "wl-1" }),
            },
        };
        var withoutWorkload = new ComplexSubject { User = new EmailSubject("jdoe@example.com") };
        var withOtherWorkload = new ComplexSubject
        {
            User = new EmailSubject("jdoe@example.com"),
            AdditionalMembers = new Dictionary<string, JsonElement>
            {
                ["workload"] = JsonSerializer.SerializeToElement(new { format = "opaque", id = "wl-2" }),
            },
        };

        Assert.True(SubjectMatcher.Matches(withWorkload, withoutWorkload));
        Assert.False(SubjectMatcher.Matches(withWorkload, withOtherWorkload));
    }
}
