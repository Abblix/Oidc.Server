// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SecurityEvents.Subjects;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Pins the SSF 1.0 half of the built-in subject vocabulary - the Complex Subject of Section 3.3
/// and the three formats of Section 3.5 - against the specification's own figures, read through
/// the same default dispatch as the RFC 9493 formats they live beside.
/// </summary>
public class SharedSignalsSubjectFormatTests
{
    [Fact]
    public void ComplexSubject_ReadsTheSpecificationFixture()
    {
        // The Complex Subject example of SSF 1.0 Section 3.3, Figure 2, verbatim.
        var subject = JsonSerializer.Deserialize<SubjectIdentifier>(
            """
            {
                "format": "complex",
                "user": {
                    "format": "email",
                    "email": "bar@example.com"
                },
                "tenant": {
                    "format": "iss_sub",
                    "iss": "https://example.com/idp1",
                    "sub": "1234"
                }
            }
            """);

        var complex = Assert.IsType<ComplexSubject>(subject);
        var user = Assert.IsType<EmailSubject>(complex.User);
        Assert.Equal("bar@example.com", user.Email);
        var tenant = Assert.IsType<IssSubSubject>(complex.Tenant);
        Assert.Equal("https://example.com/idp1", tenant.Issuer);
        Assert.Equal("1234", tenant.Subject);
        Assert.Null(complex.Device);
    }

    [Fact]
    public void ComplexSubject_RoundTrips_UnderTheAbstractType()
    {
        SubjectIdentifier original = new ComplexSubject
        {
            User = new EmailSubject("bar@example.com"),
            Session = new OpaqueSubject("session-77"),
        };

        var json = JsonSerializer.Serialize(original);
        var reread = Assert.IsType<ComplexSubject>(JsonSerializer.Deserialize<SubjectIdentifier>(json));

        Assert.Equal("bar@example.com", Assert.IsType<EmailSubject>(reread.User).Email);
        Assert.Equal("session-77", Assert.IsType<OpaqueSubject>(reread.Session).Id);
    }

    [Fact]
    public void NestedComplexSubject_IsRefused_InCodeAndOnTheWire()
    {
        // "a format field, and one or more Simple Subject Members" (SSF 1.0 Section 3.3): the
        // members of a Complex Subject are simple, so nesting dies in the same setter whether
        // the value was built in code or read off the wire.
        Assert.Throws<ArgumentException>(() => new ComplexSubject { User = new ComplexSubject() });

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<SubjectIdentifier>(
            """
            {
                "format": "complex",
                "user": { "format": "complex", "user": { "format": "opaque", "id": "u-1" } }
            }
            """));
    }

    [Fact]
    public void ComplexSubject_AdditionalMember_IsPreservedVerbatim()
    {
        // Section 3.3 allows member names beyond the registered seven; Section 3.6 wants them
        // visible to the receiver's critical-member check and intact on re-transmission.
        var subject = JsonSerializer.Deserialize<SubjectIdentifier>(
            """
            {
                "format": "complex",
                "user": { "format": "email", "email": "bar@example.com" },
                "workload": { "format": "opaque", "id": "wl-42" }
            }
            """);

        var complex = Assert.IsType<ComplexSubject>(subject);
        Assert.NotNull(complex.AdditionalMembers);
        Assert.True(complex.AdditionalMembers.ContainsKey("workload"));

        var written = JsonNode.Parse(JsonSerializer.Serialize(subject))!.AsObject();
        Assert.Equal("wl-42", written["workload"]![SubjectMemberNames.Id]!.GetValue<string>());
    }

    [Fact]
    public void JwtIdSubject_ReadsTheSpecificationFixture()
    {
        // The jwt_id example of SSF 1.0 Section 3.5.1, Figure 3, verbatim.
        var subject = JsonSerializer.Deserialize<SubjectIdentifier>(
            """
            {
                "format": "jwt_id",
                "iss": "https://idp.example.com/123456789/",
                "jti": "B70BA622-9515-4353-A866-823539EECBC8"
            }
            """);

        var jwtId = Assert.IsType<JwtIdSubject>(subject);
        Assert.Equal("https://idp.example.com/123456789/", jwtId.Issuer);
        Assert.Equal("B70BA622-9515-4353-A866-823539EECBC8", jwtId.JwtId);
    }

    [Fact]
    public void SamlAssertionIdSubject_ReadsTheSpecificationFixture()
    {
        // The saml_assertion_id example of SSF 1.0 Section 3.5.2, Figure 4, verbatim - note the
        // full-word "issuer", unlike the "iss" of jwt_id.
        var subject = JsonSerializer.Deserialize<SubjectIdentifier>(
            """
            {
                "format": "saml_assertion_id",
                "issuer": "https://idp.example.com/123456789/",
                "assertion_id": "_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6"
            }
            """);

        var assertion = Assert.IsType<SamlAssertionIdSubject>(subject);
        Assert.Equal("https://idp.example.com/123456789/", assertion.Issuer);
        Assert.Equal("_8e8dc5f69a98cc4c1ff3427e5ce34606fd672f91e6", assertion.AssertionId);
    }

    [Fact]
    public void IpAddressesSubject_ReadsTheSpecificationFixture()
    {
        // The ip-addresses example of SSF 1.0 Section 3.5.3, Figure 5, verbatim - one IPv4 and
        // one IPv6 address, both as opaque strings.
        var subject = JsonSerializer.Deserialize<SubjectIdentifier>(
            """
            {
                "format": "ip-addresses",
                "ip-addresses": ["10.29.37.75", "2001:0db8:0000:0000:0000:8a2e:0370:7334"]
            }
            """);

        var addresses = Assert.IsType<IpAddressesSubject>(subject);
        Assert.Equal(
            ["10.29.37.75", "2001:0db8:0000:0000:0000:8a2e:0370:7334"],
            addresses.IpAddresses);
    }

    [Fact]
    public void JwtIdSubject_MissingRequiredMember_IsRefused()
    {
        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<SubjectIdentifier>(
            """{"format": "jwt_id", "iss": "https://idp.example.com/"}"""));
    }

    [Fact]
    public void BuiltInSharedSignalsFormat_CannotBeRedefined_AsACustomFormat()
    {
        // The SSF names joined the built-in vocabulary, so they earn the same protection the
        // RFC 9493 names have: a custom registration cannot quietly rebind one.
        Assert.Throws<ArgumentException>(() => new SubjectIdentifierJsonConverter(
            new Dictionary<string, Type> { [SubjectFormats.JwtId] = typeof(EmailSubject) }));
    }

    [Fact]
    public void SecurityEventToken_CarriesAnSharedSignalsSubjectId_EndToEnd()
    {
        // The transmitter writes "sub_id" under the subtype's runtime shape, and the default
        // dispatch reads it back typed - no extra options anywhere.
        var token = new SecurityEventTokenBuilder()
            .WithIssuer("https://tr.example.com")
            .WithJwtId("set-1")
            .WithEvent("https://example.com/events/test")
            .WithSubjectId(new JwtIdSubject("https://idp.example.com/", "B70BA622"))
            .Build();

        var subjectId = Assert.IsType<JwtIdSubject>(token.GetSubjectId());
        Assert.Equal("B70BA622", subjectId.JwtId);
    }
}
