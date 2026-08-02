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
using System.Text.Json.Serialization;
using Abblix.SecurityEvents.Subjects;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Covers the extension door RFC 9493 leaves open: a format outside the IANA registry is a
/// subclass plus one converter registration, and the registration cannot rebind a name the
/// specification already defines.
/// </summary>
public class SubjectIdentifierCustomFormatTests
{
    /// <summary>
    /// The custom format name used across these tests. A Collision-Resistant Name, as RFC 9493
    /// Section 3 requires of formats outside the IANA registry.
    /// </summary>
    private const string TestFormat = "urn:example:test_format";

    /// <summary>
    /// A minimal custom Identifier Format: one required member, enforced through the same
    /// <see cref="SubjectIdentifier.RequirePresent"/> the registered formats use - this subclass
    /// lives in another assembly, so compiling at all proves the extension door reaches the
    /// shared guard.
    /// </summary>
    private sealed class TestSubject : SubjectIdentifier
    {
        [JsonConstructor]
        public TestSubject(string value)
            : base(TestFormat)
        {
            Value = RequirePresent(value, "value");
        }

        [JsonPropertyName("value")]
        public string Value { get; }
    }

    private static JsonSerializerOptions OptionsWithTestFormat() => new()
    {
        Converters =
        {
            new SubjectIdentifierJsonConverter(
                new Dictionary<string, Type> { [TestFormat] = typeof(TestSubject) }),
        },
    };

    [Fact]
    public void CustomFormat_RoundTrips()
    {
        var options = OptionsWithTestFormat();

        var written = JsonSerializer.Serialize<SubjectIdentifier>(new TestSubject("abc"), options);
        var parsed = JsonSerializer.Deserialize<SubjectIdentifier>(written, options);

        var custom = Assert.IsType<TestSubject>(parsed);
        Assert.Equal("abc", custom.Value);
    }

    [Fact]
    public void CustomFormat_DoesNotDisturbStandardFormats()
    {
        var options = OptionsWithTestFormat();

        var parsed = JsonSerializer.Deserialize<SubjectIdentifier>(
            """{"format":"email","email":"user@example.com"}""",
            options);

        Assert.IsType<EmailSubject>(parsed);
    }

    [Fact]
    public void UnknownFormat_IsStillRejected_WhenOnlyOtherCustomFormatsAreRegistered()
    {
        var options = OptionsWithTestFormat();

        Assert.ThrowsAny<JsonException>(
            () => JsonSerializer.Deserialize<SubjectIdentifier>("""{"format":"other","id":"1"}""", options));
    }

    [Fact]
    public void RedefiningAStandardFormat_IsRejected()
    {
        // The specification's formats are the shared vocabulary between transmitters and
        // receivers; a converter that quietly rebinds "email" would make two parties disagree
        // about a document both consider valid.
        Assert.Throws<ArgumentException>(
            () => new SubjectIdentifierJsonConverter(
                new Dictionary<string, Type> { [SubjectFormats.Email] = typeof(TestSubject) }));
    }

    [Fact]
    public void MappingToATypeOutsideTheHierarchy_IsRejected()
    {
        Assert.Throws<ArgumentException>(
            () => new SubjectIdentifierJsonConverter(
                new Dictionary<string, Type> { [TestFormat] = typeof(string) }));
    }

    [Fact]
    public void MappingToTheAbstractBase_IsRejected()
    {
        Assert.Throws<ArgumentException>(
            () => new SubjectIdentifierJsonConverter(
                new Dictionary<string, Type> { [TestFormat] = typeof(SubjectIdentifier) }));
    }

    [Fact]
    public void EmptyFormatName_IsRejected()
    {
        Assert.Throws<ArgumentException>(
            () => new SubjectIdentifierJsonConverter(
                new Dictionary<string, Type> { [string.Empty] = typeof(TestSubject) }));
    }

    [Fact]
    public void CustomFormat_EmptyRequiredMember_IsRejectedThroughTheSharedGuard()
    {
        Assert.Throws<ArgumentException>(() => new TestSubject(""));
    }

    [Fact]
    public void MappingWhoseTypeDeclaresADifferentFormat_IsRejectedOnRead()
    {
        // The registration map chose the type, but the type states its own format. Left unchecked,
        // a mapping like this would read a "urn:example:test_format" document and silently write
        // it back as "email" - two parties would then disagree about a document both consider
        // valid, which is what the redefinition guard exists to prevent.
        var options = new JsonSerializerOptions
        {
            Converters =
            {
                new SubjectIdentifierJsonConverter(
                    new Dictionary<string, Type> { [TestFormat] = typeof(EmailSubject) }),
            },
        };

        var exception = Assert.ThrowsAny<JsonException>(
            () => JsonSerializer.Deserialize<SubjectIdentifier>(
                $$"""{"format":"{{TestFormat}}","email":"user@example.com"}""",
                options));

        Assert.Contains(SubjectFormats.Email, exception.Message);
    }
}
