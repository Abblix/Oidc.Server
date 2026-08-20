// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.SecurityEvents.Subjects;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Rebuilds every JWT Claims Set RFC 8417 Section 2.1 prints through the builder and requires the
/// result to be the same JSON document. The figures were written by the specification's authors,
/// so agreement with them is evidence about conformance rather than self-report.
/// </summary>
public class SecurityEventTokenRfcFixtureTests
{
    /// <summary>
    /// Compares two claims sets as JSON values, with one equivalence on top: a single-audience
    /// "aud" is the same claim whether spelled as a string or as a one-element array
    /// (RFC 7519 Section 4.1.3 permits both spellings for one audience), and which spelling a
    /// writer picks is not a conformance fact worth failing over.
    /// </summary>
    private static void AssertSameClaimsSet(string expectedJson, JsonObject actual)
    {
        var expected = JsonNode.Parse(expectedJson);
        Assert.NotNull(expected);

        var expectedObject = Assert.IsType<JsonObject>(expected);
        NormalizeSingleAudience(expectedObject);

        var actualCopy = Assert.IsType<JsonObject>(actual.DeepClone());
        NormalizeSingleAudience(actualCopy);

        Assert.True(
            JsonNode.DeepEquals(expectedObject, actualCopy),
            $"Claims sets differ. Expected: {expectedObject.ToJsonString()} Actual: {actualCopy.ToJsonString()}");
    }

    private static void NormalizeSingleAudience(JsonObject claims)
    {
        if (claims[IanaClaimTypes.Aud] is JsonValue value && value.TryGetValue<string>(out var single))
        {
            claims[IanaClaimTypes.Aud] = new JsonArray(JsonValue.Create(single));
        }
    }

    [Fact]
    public void ScimExample_Figure1_IsRebuiltVerbatim()
    {
        // RFC 8417 Section 2.1.1: a password reset expressed as a primary event plus an extension
        // event carrying the reset count - the multiple-identifiers-one-transition case.
        var token = new SecurityEventTokenBuilder()
            .WithIssuer("https://scim.example.com")
            .WithIssuedAt(DateTimeOffset.FromUnixTimeSeconds(1458496025))
            .WithJwtId("3d0c3cf797584bd193bd0fb1bd4e7d30")
            .WithAudience(
                "https://jhub.example.com/Feeds/98d52461fa5bbc879593b7754",
                "https://jhub.example.com/Feeds/5d7604516b1d08641d7676ee7")
            .WithSubject("https://scim.example.com/Users/44f6142df96bd6ab61e7521d9")
            .WithEvent(
                "urn:ietf:params:scim:event:passwordReset",
                new JsonObject { ["id"] = "44f6142df96bd6ab61e7521d9" })
            .WithEvent(
                "https://example.com/scim/event/passwordResetExt",
                new JsonObject { ["resetAttempts"] = 5 })
            .Build();

        AssertSameClaimsSet(
            """
            {
              "iss": "https://scim.example.com",
              "iat": 1458496025,
              "jti": "3d0c3cf797584bd193bd0fb1bd4e7d30",
              "aud": [
                "https://jhub.example.com/Feeds/98d52461fa5bbc879593b7754",
                "https://jhub.example.com/Feeds/5d7604516b1d08641d7676ee7"
              ],
              "sub": "https://scim.example.com/Users/44f6142df96bd6ab61e7521d9",
              "events": {
                "urn:ietf:params:scim:event:passwordReset": {
                  "id": "44f6142df96bd6ab61e7521d9"
                },
                "https://example.com/scim/event/passwordResetExt": {
                  "resetAttempts": 5
                }
              }
            }
            """,
            token.Token.Payload.Json);
    }

    [Fact]
    [SuppressMessage("Minor Vulnerability", "S5332:Using clear-text protocols is security-sensitive",
        Justification = "The RFC 8417 Figure 2 fixture is quoted verbatim; its event identifier is a name compared as a string, not an address.")]
    public void LogoutExample_Figure2_IsRebuiltVerbatim()
    {
        // RFC 8417 Section 2.1.2: the Back-Channel Logout token - an event with no payload
        // claims, carried as the empty JSON object, plus the profile-specific "sid" envelope
        // claim, which is exactly what WithClaim exists for.
        var token = new SecurityEventTokenBuilder()
            .WithIssuer("https://server.example.com")
            .WithSubject("248289761001")
            .WithAudience("s6BhdRkqt3")
            .WithIssuedAt(DateTimeOffset.FromUnixTimeSeconds(1471566154))
            .WithJwtId("bWJq")
            .WithClaim(IanaClaimTypes.Sid, "08a5019c-17e1-4977-8f42-65a12843ea02")
            .WithEvent("http://schemas.openid.net/event/backchannel-logout")
            .Build();

        AssertSameClaimsSet(
            """
            {
              "iss": "https://server.example.com",
              "sub": "248289761001",
              "aud": "s6BhdRkqt3",
              "iat": 1471566154,
              "jti": "bWJq",
              "sid": "08a5019c-17e1-4977-8f42-65a12843ea02",
              "events": {
                "http://schemas.openid.net/event/backchannel-logout": {}
              }
            }
            """,
            token.Token.Payload.Json);
    }

    [Fact]
    public void ConsentExample_Figure3_IsRebuiltVerbatim()
    {
        // RFC 8417 Section 2.1.3: the payload's own "iss" names the issuer of the security
        // subject while the envelope's "iss" names the issuer of the event - the distinction the
        // figure exists to illustrate.
        var token = new SecurityEventTokenBuilder()
            .WithIssuer("https://my.med.example.org")
            .WithIssuedAt(DateTimeOffset.FromUnixTimeSeconds(1458496025))
            .WithJwtId("fb4e75b5411e4e19b6c0fe87950f7749")
            .WithAudience("https://rp.example.com")
            .WithEvent(
                "https://openid.net/heart/specs/consent.html",
                new JsonObject
                {
                    ["iss"] = "https://connect.example.com",
                    ["sub"] = "248289761001",
                    ["consentUri"] = new JsonArray("https://terms.med.example.org/labdisclosure.html#Agree"),
                })
            .Build();

        AssertSameClaimsSet(
            """
            {
              "iss": "https://my.med.example.org",
              "iat": 1458496025,
              "jti": "fb4e75b5411e4e19b6c0fe87950f7749",
              "aud": [
                "https://rp.example.com"
              ],
              "events": {
                "https://openid.net/heart/specs/consent.html": {
                  "iss": "https://connect.example.com",
                  "sub": "248289761001",
                  "consentUri": [
                    "https://terms.med.example.org/labdisclosure.html#Agree"
                  ]
                }
              }
            }
            """,
            token.Token.Payload.Json);
    }

    [Fact]
    public void RiscExample_Figure4_IsRebuiltVerbatim()
    {
        // RFC 8417 Section 2.1.4: an account-disabled event whose subject sits inside the event
        // payload. The figure predates RFC 9493 - its "subject_type"/"iss-sub" spelling is the
        // old RISC one - so the payload rides through as data, exactly as a receiver of history
        // must accept it.
        var token = new SecurityEventTokenBuilder()
            .WithIssuer("https://idp.example.com/")
            .WithJwtId("756E69717565206964656E746966696572")
            .WithIssuedAt(DateTimeOffset.FromUnixTimeSeconds(1508184845))
            .WithAudience("636C69656E745F6964")
            .WithEvent(
                "https://schemas.openid.net/secevent/risc/event-type/account-disabled",
                new JsonObject
                {
                    ["subject"] = new JsonObject
                    {
                        ["subject_type"] = "iss-sub",
                        ["iss"] = "https://idp.example.com/",
                        ["sub"] = "7375626A656374",
                    },
                    ["reason"] = "hijacking",
                })
            .Build();

        AssertSameClaimsSet(
            """
            {
              "iss": "https://idp.example.com/",
              "jti": "756E69717565206964656E746966696572",
              "iat": 1508184845,
              "aud": "636C69656E745F6964",
              "events": {
                "https://schemas.openid.net/secevent/risc/event-type/account-disabled": {
                  "subject": {
                    "subject_type": "iss-sub",
                    "iss": "https://idp.example.com/",
                    "sub": "7375626A656374"
                  },
                  "reason": "hijacking"
                }
              }
            }
            """,
            token.Token.Payload.Json);
    }

    [Fact]
    public void ModelView_ReadsTheScimFigureBack()
    {
        // The same figure through the reading door: a token whose payload arrived as JSON, viewed
        // through the typed accessors.
        var payload = JsonNode.Parse(
            """
            {
              "iss": "https://scim.example.com",
              "iat": 1458496025,
              "jti": "3d0c3cf797584bd193bd0fb1bd4e7d30",
              "aud": [
                "https://jhub.example.com/Feeds/98d52461fa5bbc879593b7754",
                "https://jhub.example.com/Feeds/5d7604516b1d08641d7676ee7"
              ],
              "sub": "https://scim.example.com/Users/44f6142df96bd6ab61e7521d9",
              "events": {
                "urn:ietf:params:scim:event:passwordReset": {
                  "id": "44f6142df96bd6ab61e7521d9"
                },
                "https://example.com/scim/event/passwordResetExt": {
                  "resetAttempts": 5
                }
              }
            }
            """);

        var token = new SecurityEventToken(
            new JsonWebToken { Payload = new JsonWebTokenPayload((JsonObject)payload!) });

        Assert.Equal("https://scim.example.com", token.Issuer);
        Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1458496025), token.IssuedAt);
        Assert.Equal("3d0c3cf797584bd193bd0fb1bd4e7d30", token.JwtId);
        Assert.Equal(2, token.Audiences.Count());
        Assert.Equal("https://scim.example.com/Users/44f6142df96bd6ab61e7521d9", token.Subject);

        var events = token.Events;
        Assert.NotNull(events);
        Assert.Equal(2, events.Count);
        Assert.True(events.TryGetPayload("urn:ietf:params:scim:event:passwordReset", out var reset));
        Assert.Equal("44f6142df96bd6ab61e7521d9", (string?)reset["id"]);
    }

    [Fact]
    public void SubjectIdentifier_TravelsInsideAnEventPayload()
    {
        // The two layers of this package meeting: an RFC 9493 subject serialized into an
        // RFC 8417 event payload, the composition every Shared Signals event uses.
        var subject = JsonSerializer.SerializeToNode<SubjectIdentifier>(
            new IssSubSubject("https://account.example.com", "a3f1c9e2"));

        var token = new SecurityEventTokenBuilder()
            .WithIssuer("https://tenant.example.com")
            .WithJwtId("evt-1")
            .WithIssuedAt(DateTimeOffset.FromUnixTimeSeconds(1754040000))
            .WithEvent(
                "https://tenant.example.com/events/membership-changed",
                new JsonObject { ["subject"] = subject, ["change"] = "revoked" })
            .Build();

        var events = token.Events;
        Assert.NotNull(events);
        Assert.True(events.TryGetPayload("https://tenant.example.com/events/membership-changed", out var payload));

        var parsed = payload["subject"].Deserialize<SubjectIdentifier>();
        var issSub = Assert.IsType<IssSubSubject>(parsed);
        Assert.Equal("https://account.example.com", issSub.Issuer);
        Assert.Equal("a3f1c9e2", issSub.Subject);
    }
}
