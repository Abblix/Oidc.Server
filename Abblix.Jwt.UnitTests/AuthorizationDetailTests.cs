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
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Unit tests for <see cref="AuthorizationDetail"/> and the <see cref="JsonWebTokenPayload.AuthorizationDetails"/>
/// accessor. Covers JSON round-trip of standardised RFC 9396 §2.2 members, extension-data preservation for
/// type-specific payload, and the typed accessor mechanics on the payload.
/// </summary>
public class AuthorizationDetailTests
{
    [Fact]
    public void IanaClaimTypes_AuthorizationDetails_Constant_HasExpectedWireValue()
    {
        Assert.Equal("authorization_details", IanaClaimTypes.AuthorizationDetails);
    }

    /// <summary>
    /// Standardised RFC 9396 §2.2 members survive JSON serialise → deserialise round-trip with
    /// member-by-member equality. No extension data in this case.
    /// </summary>
    [Fact]
    public void Serialize_StandardisedMembers_RoundTripPreservesAll()
    {
        var original = new AuthorizationDetail
        {
            Type = "payment_initiation",
            Locations = new[] { "https://api.bank.example/payments" },
            Actions = new[] { "initiate", "status" },
            Datatypes = new[] { "iban" },
            Identifier = "txn-4521",
            Privileges = new[] { "read", "write" },
        };

        var json = JsonSerializer.Serialize(original);
        var round = JsonSerializer.Deserialize<AuthorizationDetail>(json);

        Assert.NotNull(round);
        Assert.Equal(original.Type, round.Type);
        Assert.Equal(original.Locations, round.Locations);
        Assert.Equal(original.Actions, round.Actions);
        Assert.Equal(original.Datatypes, round.Datatypes);
        Assert.Equal(original.Identifier, round.Identifier);
        Assert.Equal(original.Privileges, round.Privileges);
        Assert.Null(round.ExtensionData);
    }

    /// <summary>
    /// Type-specific members outside the RFC 9396 §2.2 common-data set land in
    /// <see cref="AuthorizationDetail.ExtensionData"/> and survive round-trip with their original
    /// JSON shape — strings, numbers, nested objects, nested arrays.
    /// </summary>
    [Fact]
    public void Serialize_TypeSpecificMembers_PreservedInExtensionData()
    {
        const string wire =
            """
            {
              "type": "payment_initiation",
              "actions": ["initiate"],
              "instructedAmount": { "currency": "EUR", "amount": "500.00" },
              "creditorAccount": { "iban": "DE02100100109307118603" },
              "creditorName": "Merchant A",
              "remittanceInformationUnstructured": "Order #4521",
              "lineItems": [
                { "id": "li-1", "qty": 2 },
                { "id": "li-2", "qty": 1 }
              ]
            }
            """;

        var detail = JsonSerializer.Deserialize<AuthorizationDetail>(wire);

        Assert.NotNull(detail);
        Assert.Equal("payment_initiation", detail.Type);
        Assert.Equal(new[] { "initiate" }, detail.Actions);
        Assert.NotNull(detail.ExtensionData);
        Assert.True(detail.ExtensionData.ContainsKey("instructedAmount"));
        Assert.True(detail.ExtensionData.ContainsKey("creditorAccount"));
        Assert.True(detail.ExtensionData.ContainsKey("creditorName"));
        Assert.True(detail.ExtensionData.ContainsKey("remittanceInformationUnstructured"));
        Assert.True(detail.ExtensionData.ContainsKey("lineItems"));

        // Re-serialise and re-deserialise to confirm extension members survive a second pass.
        var roundJson = JsonSerializer.Serialize(detail);
        var round = JsonSerializer.Deserialize<AuthorizationDetail>(roundJson);

        Assert.NotNull(round);
        Assert.Equal(detail.ExtensionData.Count, round.ExtensionData?.Count);
        Assert.Equal(
            "Merchant A",
            round.ExtensionData!["creditorName"].GetString());
        Assert.Equal(
            "EUR",
            round.ExtensionData["instructedAmount"].GetProperty("currency").GetString());
        Assert.Equal(
            2,
            round.ExtensionData["lineItems"].GetArrayLength());
    }

    /// <summary>
    /// Verifies the <see cref="JsonWebTokenPayload.AuthorizationDetails"/> accessor reads an
    /// existing JSON array from the underlying claim and projects each element into the typed
    /// model, including type-specific extension data.
    /// </summary>
    [Fact]
    public void Payload_AuthorizationDetails_ReadsArrayFromUnderlyingJson()
    {
        var json = new JsonObject
        {
            [IanaClaimTypes.AuthorizationDetails] = JsonNode.Parse(
                """
                [
                  { "type": "payment_initiation", "actions": ["initiate"], "amount": "500.00" },
                  { "type": "account_information", "locations": ["https://api.bank.example/accounts"] }
                ]
                """),
        };
        var payload = new JsonWebTokenPayload(json);

        var details = payload.AuthorizationDetails?.ToArray();

        Assert.NotNull(details);
        Assert.Equal(2, details.Length);

        Assert.Equal("payment_initiation", details[0].Type);
        Assert.Equal(new[] { "initiate" }, details[0].Actions);
        Assert.Equal("500.00", details[0].ExtensionData?["amount"].GetString());

        Assert.Equal("account_information", details[1].Type);
        Assert.Equal(new[] { "https://api.bank.example/accounts" }, details[1].Locations);
        Assert.Null(details[1].ExtensionData);
    }

    /// <summary>
    /// Verifies the setter projects each typed detail back into a JSON array under the canonical
    /// claim name, including extension-data members. Re-reading via the getter yields equality
    /// on the standardised + type-specific members.
    /// </summary>
    [Fact]
    public void Payload_AuthorizationDetails_WritesArrayAndRoundTrips()
    {
        var details = new[]
        {
            new AuthorizationDetail
            {
                Type = "payment_initiation",
                Actions = new[] { "initiate" },
                ExtensionData = new Dictionary<string, JsonElement>
                {
                    ["instructedAmount"] = JsonDocument.Parse("""{"currency":"EUR","amount":"500.00"}""").RootElement,
                },
            },
            new AuthorizationDetail
            {
                Type = "account_information",
                Locations = new[] { "https://api.bank.example/accounts" },
            },
        };

        var payload = new JsonWebTokenPayload(new JsonObject())
        {
            AuthorizationDetailsRaw = details.ToRawJsonArray(),
        };

        Assert.IsType<JsonArray>(payload.Json[IanaClaimTypes.AuthorizationDetails]);

        var round = payload.AuthorizationDetails?.ToArray();

        Assert.NotNull(round);
        Assert.Equal(2, round.Length);
        Assert.Equal("payment_initiation", round[0].Type);
        Assert.Equal(new[] { "initiate" }, round[0].Actions);
        Assert.Equal(
            "EUR",
            round[0].ExtensionData?["instructedAmount"].GetProperty("currency").GetString());
        Assert.Equal("account_information", round[1].Type);
        Assert.Equal(new[] { "https://api.bank.example/accounts" }, round[1].Locations);
    }

    /// <summary>
    /// Assigning <c>null</c> removes the claim from the underlying JSON object so the payload
    /// does not carry an empty marker.
    /// </summary>
    [Fact]
    public void Payload_AuthorizationDetails_SetNullRemovesClaim()
    {
        var payload = new JsonWebTokenPayload(new JsonObject())
        {
            AuthorizationDetailsRaw = new[] { new AuthorizationDetail { Type = "x" } }.ToRawJsonArray(),
        };
        Assert.True(payload.Json.ContainsKey(IanaClaimTypes.AuthorizationDetails));

        payload.AuthorizationDetailsRaw = null;

        Assert.False(payload.Json.ContainsKey(IanaClaimTypes.AuthorizationDetails));
        Assert.Null(payload.AuthorizationDetails);
        Assert.Null(payload.AuthorizationDetailsRaw);
    }

    /// <summary>
    /// When the claim is absent (or not a JSON array, e.g. malformed external input) the getter
    /// returns <c>null</c> rather than throwing, so callers downstream of the validator are not
    /// surprised by exceptions when reading a not-present claim.
    /// </summary>
    [Theory]
    [InlineData("""{}""")]
    [InlineData("""{ "authorization_details": null }""")]
    [InlineData("""{ "authorization_details": "not-an-array" }""")]
    [InlineData("""{ "authorization_details": { "type": "payment_initiation" } }""")]
    public void Payload_AuthorizationDetails_AbsentOrMalformedYieldsNull(string wire)
    {
        var json = (JsonObject)JsonNode.Parse(wire)!;
        var payload = new JsonWebTokenPayload(json);

        Assert.Null(payload.AuthorizationDetails);
    }
}
