// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SharedSignals.Model;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the transmitter configuration metadata against the member names and optionality
/// SSF 1.0 Section 7.1 fixes.
/// </summary>
public class TransmitterConfigurationTests
{
    /// <summary>
    /// A metadata document shaped like the architecture's transmitter: issuer, keys, both
    /// delivery methods, the management endpoints. Member names verbatim from Section 7.1.
    /// </summary>
    private const string MetadataFixture =
        """
        {
            "spec_version": "1_0",
            "issuer": "https://tenant.example.com",
            "jwks_uri": "https://tenant.example.com/.well-known/jwks.json",
            "delivery_methods_supported": ["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"],
            "configuration_endpoint": "https://tenant.example.com/ssf/streams",
            "status_endpoint": "https://tenant.example.com/ssf/status",
            "verification_endpoint": "https://tenant.example.com/ssf/verification",
            "authorization_schemes": [{ "spec_urn": "urn:ietf:rfc:6749" }],
            "default_subjects": "ALL"
        }
        """;

    [Fact]
    public void Metadata_ReadsEveryMemberBySpecificationName()
    {
        var metadata = JsonSerializer.Deserialize<TransmitterConfiguration>(MetadataFixture);

        Assert.NotNull(metadata);
        Assert.Equal("1_0", metadata.SpecVersion);
        Assert.Equal("https://tenant.example.com", metadata.Issuer);
        Assert.Equal(new Uri("https://tenant.example.com/.well-known/jwks.json"), metadata.JwksUri);
        Assert.Equal(["urn:ietf:rfc:8935", "urn:ietf:rfc:8936"], metadata.DeliveryMethodsSupported);
        Assert.Equal(new Uri("https://tenant.example.com/ssf/streams"), metadata.ConfigurationEndpoint);
        Assert.Equal(new Uri("https://tenant.example.com/ssf/status"), metadata.StatusEndpoint);
        Assert.Equal(new Uri("https://tenant.example.com/ssf/verification"), metadata.VerificationEndpoint);
        Assert.Equal(TransmitterConfiguration.DefaultSubjectBehaviors.All, metadata.DefaultSubjects);
        var scheme = Assert.Single(metadata.AuthorizationSchemes!);
        Assert.Equal("urn:ietf:rfc:6749", scheme["spec_urn"]!.GetValue<string>());
    }

    [Fact]
    public void Metadata_WithOnlyTheRequiredIssuer_ReadsAndWritesMinimal()
    {
        var metadata = JsonSerializer.Deserialize<TransmitterConfiguration>(
            """{"issuer": "https://tr.example.com"}""");

        Assert.NotNull(metadata);
        Assert.Equal("https://tr.example.com", metadata.Issuer);
        Assert.Null(metadata.SpecVersion);
        Assert.Null(metadata.JwksUri);

        // Optional members stay off the wire entirely rather than traveling as nulls.
        var written = JsonNode.Parse(JsonSerializer.Serialize(metadata))!.AsObject();
        var member = Assert.Single(written);
        Assert.Equal(TransmitterConfiguration.ParameterNames.Issuer, member.Key);
    }

    [Fact]
    public void Metadata_WithoutIssuer_IsRefused()
    {
        // The one member Section 7.1 marks REQUIRED cannot be defaulted into existence.
        Assert.Throws<JsonException>(
            () => JsonSerializer.Deserialize<TransmitterConfiguration>("""{"spec_version": "1_0"}"""));
    }

    [Fact]
    public void WellKnownAddress_WithoutAPathComponent_AppendsTheSegment()
    {
        // SSF 1.0 Section 7.2.1, Figure 16: "https://tr.example.com" has no path, so the
        // insertion degenerates to a plain append.
        Assert.Equal(
            new Uri("https://tr.example.com/.well-known/ssf-configuration"),
            TransmitterConfiguration.WellKnownAddress(new Uri("https://tr.example.com")));
    }

    [Fact]
    public void WellKnownAddress_WithAPathComponent_InsertsBetweenHostAndPath()
    {
        // SSF 1.0 Section 7.2.1, Figure 17: the segment goes BETWEEN host and path - a naive
        // suffix would produce ".../issuer1/.well-known/..." and miss multi-tenant issuers.
        Assert.Equal(
            new Uri("https://tr.example.com/.well-known/ssf-configuration/issuer1"),
            TransmitterConfiguration.WellKnownAddress(new Uri("https://tr.example.com/issuer1")));
    }

    [Fact]
    public void WellKnownAddress_RemovesTheTerminatingSlash_BeforeInserting()
    {
        // "any terminating '/' MUST be removed before inserting" (SSF 1.0 Section 7.2.1).
        Assert.Equal(
            new Uri("https://tr.example.com/.well-known/ssf-configuration/issuer1"),
            TransmitterConfiguration.WellKnownAddress(new Uri("https://tr.example.com/issuer1/")));
    }

    [Fact]
    public void WellKnownAddress_CleartextIssuer_IsRefused_ExceptOnLoopback()
    {
        // The document behind the address names every endpoint and the signing keys; over
        // cleartext the whole trust anchor is whoever sits on the path. A developer's loopback
        // offers no path to sit on.
        Assert.Throws<ArgumentException>(
            () => TransmitterConfiguration.WellKnownAddress(new Uri("http://tr.example.com")));

        Assert.Equal(
            new Uri("http://localhost:5000/.well-known/ssf-configuration"),
            TransmitterConfiguration.WellKnownAddress(new Uri("http://localhost:5000")));
    }

    [Fact]
    public void WellKnownAddress_IssuerWithQueryOrFragment_IsRefused()
    {
        // An issuer identifier has no room for either (SSF 1.0 Section 7.1).
        Assert.Throws<ArgumentException>(
            () => TransmitterConfiguration.WellKnownAddress(new Uri("https://tr.example.com/a?x=1")));
        Assert.Throws<ArgumentException>(
            () => TransmitterConfiguration.WellKnownAddress(new Uri("https://tr.example.com/a#frag")));
    }
}
