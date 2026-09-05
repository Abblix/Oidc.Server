// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using Abblix.SecurityEvents.Subjects;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Pins the conditions RFC 9493 Section 3.2.8 places on the Aliases Identifier Format, on both
/// doors: values built in code and values arriving over the wire must die on the same rule.
/// </summary>
public class AliasesSubjectTests
{
    [Fact]
    public void NestedAliases_IsRejected_OnConstruction()
    {
        var inner = new AliasesSubject(new EmailSubject("user@example.com"));

        var exception = Assert.Throws<ArgumentException>(
            () => new AliasesSubject(new OpaqueSubject("123"), inner));

        Assert.Contains("RFC 9493", exception.Message);
    }

    [Fact]
    public void NestedAliases_IsRejected_FromTheWire()
    {
        // The document is well-formed JSON; only the specification's MUST NOT makes it invalid.
        // Rejection must therefore come from our own rule, re-labelled as JsonException at the
        // deserialization boundary, not from the JSON parser.
        var json =
            """
            {
              "format": "aliases",
              "identifiers": [
                {
                  "format": "aliases",
                  "identifiers": [ { "format": "email", "email": "user@example.com" } ]
                }
              ]
            }
            """;

        Assert.ThrowsAny<JsonException>(() => JsonSerializer.Deserialize<SubjectIdentifier>(json));
    }

    [Fact]
    public void EmptyIdentifiers_IsRejected()
    {
        Assert.Throws<ArgumentException>(() => new AliasesSubject());
        Assert.ThrowsAny<JsonException>(
            () => JsonSerializer.Deserialize<SubjectIdentifier>("""{"format":"aliases","identifiers":[]}"""));
    }

    [Fact]
    public void MutatingTheSourceList_DoesNotReachTheConstructedValue()
    {
        // The constructor's checks hold only if what was validated is what the object keeps: were
        // the caller's list stored by reference, clearing it or inserting a nested alias would
        // break both RFC MUSTs on an object already documented as valid.
        var source = new List<SubjectIdentifier> { new EmailSubject("user@example.com") };
        var aliases = new AliasesSubject(source);

        source.Add(new AliasesSubject(new OpaqueSubject("123")));
        source.Clear();

        var kept = Assert.Single(aliases.Identifiers);
        Assert.Equal("user@example.com", Assert.IsType<EmailSubject>(kept).Email);
    }

    [Fact]
    public void NullIdentifierList_IsRejected()
    {
        Assert.Throws<ArgumentNullException>(
            () => new AliasesSubject((IReadOnlyList<SubjectIdentifier>)null!));
    }

    [Fact]
    public void NullEntry_IsRejected()
    {
        Assert.Throws<ArgumentException>(
            () => new AliasesSubject(new EmailSubject("user@example.com"), null!));
    }

    [Fact]
    public void DuplicateEntries_AreKept()
    {
        // RFC 9493 Section 3.2.8 says exact duplicates SHOULD NOT appear. A SHOULD NOT binds the
        // producing application, not this library: silently deduplicating here would change what
        // the caller said without telling anyone.
        var duplicate = new AliasesSubject(
            new EmailSubject("user@example.com"),
            new EmailSubject("user@example.com"));

        Assert.Equal(2, duplicate.Identifiers.Count);
    }

    [Fact]
    public void SameFormatTwice_IsAllowed()
    {
        // "It MAY contain multiple instances of the same Identifier Format" (RFC 9493
        // Section 3.2.8) - the RFC's own Figure 13 relies on this with its two email entries.
        var aliases = new AliasesSubject(
            new EmailSubject("user@example.com"),
            new EmailSubject("user+qualifier@example.com"));

        Assert.Equal(2, aliases.Identifiers.Count);
    }
}
