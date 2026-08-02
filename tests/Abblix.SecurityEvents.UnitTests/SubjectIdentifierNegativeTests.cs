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
using Abblix.SecurityEvents.Subjects;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Documents that RFC 9493 Section 3 conditions actually reject rather than pass silently. Each
/// input here violates a specific normative sentence, so a green run is evidence that the MUSTs
/// are enforced and not merely quoted in documentation.
/// </summary>
public class SubjectIdentifierNegativeTests
{
    [Theory]
    // Not a JSON object at all: "A Subject Identifier is a JSON object" (RFC 9493 Section 3).
    [InlineData("\"email\"")]
    [InlineData("42")]
    [InlineData("[]")]
    // No "format" member: "MUST contain a 'format' member" (RFC 9493 Section 3).
    [InlineData("""{"email":"user@example.com"}""")]
    // A "format" member that is not a string names no Identifier Format.
    [InlineData("""{"format":42,"email":"user@example.com"}""")]
    [InlineData("""{"format":null,"email":"user@example.com"}""")]
    [InlineData("""{"format":"","email":"user@example.com"}""")]
    // A format neither registered by RFC 9493 nor supplied as a custom format.
    [InlineData("""{"format":"unknown_format","id":"123"}""")]
    public void MalformedDocument_IsRejectedAsJson(string json)
    {
        Assert.ThrowsAny<JsonException>(() => JsonSerializer.Deserialize<SubjectIdentifier>(json));
    }

    [Theory]
    // A required member absent entirely: "The 'email' member is REQUIRED" and its siblings
    // (RFC 9493 Sections 3.2.1 through 3.2.8).
    [InlineData("""{"format":"account"}""")]
    [InlineData("""{"format":"email"}""")]
    [InlineData("""{"format":"iss_sub","sub":"145234573"}""")]
    [InlineData("""{"format":"iss_sub","iss":"https://issuer.example.com/"}""")]
    [InlineData("""{"format":"opaque"}""")]
    [InlineData("""{"format":"phone_number"}""")]
    [InlineData("""{"format":"did"}""")]
    [InlineData("""{"format":"uri"}""")]
    [InlineData("""{"format":"aliases"}""")]
    // A required member present but null or empty: "MUST NOT be null or empty".
    [InlineData("""{"format":"email","email":null}""")]
    [InlineData("""{"format":"email","email":""}""")]
    [InlineData("""{"format":"iss_sub","iss":"","sub":"145234573"}""")]
    [InlineData("""{"format":"opaque","id":""}""")]
    [InlineData("""{"format":"aliases","identifiers":null}""")]
    public void MissingOrEmptyRequiredMember_IsRejected(string json)
    {
        // The rejection originates in the subtype's own constructor - the same code path that
        // stops the value being built in memory - and the converter re-labels it as JsonException
        // at the wire boundary, so a caller guarding untrusted input catches one exception type
        // however the document is invalid.
        Assert.ThrowsAny<JsonException>(() => JsonSerializer.Deserialize<SubjectIdentifier>(json));
    }

    [Theory]
    // A member the Identifier Format does not describe: "A Subject Identifier MUST NOT contain
    // any members prohibited or not described by its Identifier Format" (RFC 9493 Section 3).
    // Accepting these would be worse than leniency - the next serialization would silently drop
    // the member and emit a different document than the one received.
    [InlineData("""{"format":"email","email":"user@example.com","id":"123"}""")]
    [InlineData("""{"format":"opaque","id":"123","email":"user@example.com"}""")]
    [InlineData("""{"format":"iss_sub","iss":"https://issuer.example.com/","sub":"1","uri":"x"}""")]
    public void MemberNotDescribedByTheFormat_IsRejected(string json)
    {
        Assert.ThrowsAny<JsonException>(() => JsonSerializer.Deserialize<SubjectIdentifier>(json));
    }

    [Fact]
    public void JsonNull_DeserializesToNull_NotToAnError()
    {
        // A JSON null is not a malformed Subject Identifier but the absence of one: the serializer
        // returns a null reference without consulting the converter, per its contract for
        // reference types. Where presence is required, the requirer enforces it - a null here
        // becoming an error is the business of the validation step that needed a subject.
        Assert.Null(JsonSerializer.Deserialize<SubjectIdentifier>("null"));
    }

    [Fact]
    public void EmptyRequiredMember_IsRejected_OnConstructionToo()
    {
        // The wire tests above originate in the same constructors these calls hit directly; the
        // difference is only the label at the boundary - ArgumentException in code, JsonException
        // once the converter translates it for a deserializing caller.
        Assert.Throws<ArgumentException>(() => new EmailSubject(""));
        Assert.Throws<ArgumentException>(() => new IssSubSubject("https://issuer.example.com/", ""));
        Assert.Throws<ArgumentException>(() => new OpaqueSubject(""));
    }

    [Fact]
    public void ConcreteDeclaredRead_TakesTheCallerAtItsWord()
    {
        // Deserializing into a CONCRETE declared type bypasses the polymorphic converter, so the
        // "format" member is not consulted there: the caller already named the type, and the wire
        // value binds to nothing (the Format property is read-only). This pins that door's
        // behaviour so it reads as a decision, not an accident - the polymorphic door is the wire
        // door, and code that reads untrusted input must declare the base type.
        var parsed = JsonSerializer.Deserialize<EmailSubject>(
            """{"format":"phone_number","email":"user@example.com"}""");

        Assert.NotNull(parsed);
        Assert.Equal(SubjectFormats.Email, parsed.Format);
    }
}
