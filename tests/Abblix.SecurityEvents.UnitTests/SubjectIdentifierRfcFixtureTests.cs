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
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Round-trips every Subject Identifier example RFC 9493 prints, verbatim from the document.
/// The fixtures are the interop oracle: they were written by the specification's authors, not by
/// this library, so agreement with them is evidence about conformance rather than self-report.
/// </summary>
public class SubjectIdentifierRfcFixtureTests
{
    /// <summary>
    /// The examples of RFC 9493 Sections 3.2.1 through 3.2.8 (Figures 4 through 13), each paired
    /// with the concrete type the "format" member must select.
    /// </summary>
    public static TheoryData<string, Type> RfcExamples => new()
    {
        // Figure 4, Section 3.2.1
        {
            """
            {
              "format": "account",
              "uri": "acct:example.user@service.example.com"
            }
            """,
            typeof(AccountSubject)
        },
        // Figure 5, Section 3.2.2
        {
            """
            {
              "format": "email",
              "email": "user@example.com"
            }
            """,
            typeof(EmailSubject)
        },
        // Figure 6, Section 3.2.3
        {
            """
            {
              "format": "iss_sub",
              "iss": "https://issuer.example.com/",
              "sub": "145234573"
            }
            """,
            typeof(IssSubSubject)
        },
        // Figure 7, Section 3.2.4
        {
            """
            {
              "format": "opaque",
              "id": "11112222333344445555"
            }
            """,
            typeof(OpaqueSubject)
        },
        // Figure 8, Section 3.2.5
        {
            """
            {
              "format": "phone_number",
              "phone_number": "+12065550100"
            }
            """,
            typeof(PhoneNumberSubject)
        },
        // Figure 9, Section 3.2.6: a bare DID
        {
            """
            {
              "format": "did",
              "url": "did:example:123456"
            }
            """,
            typeof(DidSubject)
        },
        // Figure 10, Section 3.2.6: a DID URL with path and query
        {
            """
            {
              "format": "did",
              "url": "did:example:123456/did/url/path?versionId=1"
            }
            """,
            typeof(DidSubject)
        },
        // Figure 11, Section 3.2.7: a website URI
        {
            """
            {
              "format": "uri",
              "uri": "https://user.example.com/"
            }
            """,
            typeof(UriSubject)
        },
        // Figure 12, Section 3.2.7: a random URN
        {
            """
            {
              "format": "uri",
              "uri": "urn:uuid:4e851e98-83c4-4743-a5da-150ecb53042f"
            }
            """,
            typeof(UriSubject)
        },
        // Figure 13, Section 3.2.8: aliases holding two emails and a phone number
        {
            """
            {
              "format": "aliases",
              "identifiers": [
                {
                  "format": "email",
                  "email": "user@example.com"
                },
                {
                  "format": "phone_number",
                  "phone_number": "+12065550100"
                },
                {
                  "format": "email",
                  "email": "user+qualifier@example.com"
                }
              ]
            }
            """,
            typeof(AliasesSubject)
        },
    };

    [Theory]
    [MemberData(nameof(RfcExamples))]
    public void RfcExample_RoundTrips_ToTheSameDocument(string fixture, Type expectedType)
    {
        var parsed = JsonSerializer.Deserialize<SubjectIdentifier>(fixture);

        Assert.NotNull(parsed);
        Assert.IsType(expectedType, parsed);

        var written = JsonSerializer.Serialize(parsed);

        // Equality is by JSON value, so member order and whitespace do not participate: the RFC's
        // pretty-printed fixture and our compact output must still be the same document.
        Assert.True(
            JsonNode.DeepEquals(JsonNode.Parse(fixture), JsonNode.Parse(written)),
            $"Round-tripped JSON differs from the RFC fixture. Fixture: {fixture} Written: {written}");
    }

    [Fact]
    public void IssSubExample_ParsesIntoBothMembers()
    {
        var parsed = JsonSerializer.Deserialize<SubjectIdentifier>(
            """{"format":"iss_sub","iss":"https://issuer.example.com/","sub":"145234573"}""");

        var issSub = Assert.IsType<IssSubSubject>(parsed);
        Assert.Equal("https://issuer.example.com/", issSub.Issuer);
        Assert.Equal("145234573", issSub.Subject);
    }

    [Fact]
    public void AliasesExample_ParsesNestedIdentifiersPolymorphically()
    {
        var parsed = JsonSerializer.Deserialize<SubjectIdentifier>(
            """
            {
              "format": "aliases",
              "identifiers": [
                { "format": "email", "email": "user@example.com" },
                { "format": "phone_number", "phone_number": "+12065550100" },
                { "format": "email", "email": "user+qualifier@example.com" }
              ]
            }
            """);

        var aliases = Assert.IsType<AliasesSubject>(parsed);
        Assert.Collection(
            aliases.Identifiers,
            first => Assert.Equal("user@example.com", Assert.IsType<EmailSubject>(first).Email),
            second => Assert.Equal("+12065550100", Assert.IsType<PhoneNumberSubject>(second).PhoneNumber),
            third => Assert.Equal("user+qualifier@example.com", Assert.IsType<EmailSubject>(third).Email));
    }

    [Fact]
    public void Serialization_PutsFormatFirst_MatchingTheRfcExamplesAsText()
    {
        var written = JsonSerializer.Serialize<SubjectIdentifier>(new EmailSubject("user@example.com"));

        Assert.Equal("""{"format":"email","email":"user@example.com"}""", written);
    }

    [Fact]
    public void Serialization_OfConcreteDeclaredType_StillCarriesFormat()
    {
        // The converter sits on the abstract base, so a value serialized under its concrete
        // compile-time type takes a different path through the serializer. The "format" member is
        // REQUIRED (RFC 9493 Section 3) on both paths, which is exactly the two-door trap the
        // sibling JWK hierarchy documents.
        var written = JsonSerializer.Serialize(new EmailSubject("user@example.com"));

        Assert.Equal("""{"format":"email","email":"user@example.com"}""", written);
    }
}
