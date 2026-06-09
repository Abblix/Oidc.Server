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

using System.Text.Json.Nodes;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Unit tests for <see cref="AuthorizationDetail"/> as a thin wrapper over a
/// <see cref="JsonNode"/> claim element and the <see cref="JsonWebTokenPayload.AuthorizationDetails"/>
/// accessor. Verifies that the wrapper's typed property accessors read from and write to the
/// underlying JSON in place — so member order and type-specific extension members survive the
/// authorize → code → token round-trip byte-exact.
/// </summary>
public class AuthorizationDetailTests
{
    // RFC 9396 §2.2 example types / actions reused across fixtures.
    private const string PaymentInitiationType = "payment_initiation";
    private const string InitiateAction = "initiate";


    [Fact]
    public void IanaClaimTypes_AuthorizationDetails_Constant_HasExpectedWireValue()
    {
        Assert.Equal("authorization_details", IanaClaimTypes.AuthorizationDetails);
    }

    [Fact]
    public void TypedAccessors_ReadFromUnderlyingJson()
    {
        var json = (JsonObject)JsonNode.Parse(
            """
            {
              "type": "payment_initiation",
              "locations": ["https://api.bank.example/payments"],
              "actions": ["initiate", "status"],
              "datatypes": ["iban"],
              "identifier": "txn-4521",
              "privileges": ["read", "write"]
            }
            """)!;
        var detail = new AuthorizationDetail(json);

        Assert.Equal(PaymentInitiationType, detail.Type);
        Assert.Equal(new[] { "https://api.bank.example/payments" }, detail.Locations);
        Assert.Equal(new[] { InitiateAction, "status" }, detail.Actions);
        Assert.Equal(new[] { "iban" }, detail.Datatypes);
        Assert.Equal("txn-4521", detail.Identifier);
        Assert.Equal(new[] { "read", "write" }, detail.Privileges);
    }

    [Fact]
    public void TypedSetters_MutateUnderlyingJsonInPlace()
    {
        var json = new JsonObject();
        var detail = new AuthorizationDetail(json)
        {
            Type = PaymentInitiationType,
            Actions = new[] { InitiateAction, "status" },
        };

        Assert.Equal(PaymentInitiationType, json["type"]?.GetValue<string>());
        // Multi-element arrays land as a JsonArray; single-element collapses to a string per
        // the OAuth single-or-array convention shared with audience / amr.
        Assert.IsType<JsonArray>(json["actions"]);
        Assert.Equal(2, json["actions"]!.AsArray().Count);

        // Setter on wrapper writes through to the same underlying JsonObject reference.
        Assert.Same(json, detail.Json);
    }

    [Fact]
    public void TypeSpecificMembers_AccessedDirectlyViaJson()
    {
        // RFC 9396 §2.2 extension members (per-type payload like PSD2 instructedAmount /
        // creditorAccount) live in the wrapper's Json as ordinary JSON members; per-type
        // validators read and write them directly through the System.Text.Json.Nodes API.
        var json = (JsonObject)JsonNode.Parse(
            """
            {
              "type": "payment_initiation",
              "actions": ["initiate"],
              "instructedAmount": { "currency": "EUR", "amount": "500.00" },
              "creditorAccount": { "iban": "DE02100100109307118603" },
              "lineItems": [{ "id": "li-1", "qty": 2 }, { "id": "li-2", "qty": 1 }]
            }
            """)!;
        var detail = new AuthorizationDetail(json);

        Assert.Equal(PaymentInitiationType, detail.Type);
        Assert.Equal(new[] { InitiateAction }, detail.Actions);
        Assert.Equal("EUR", detail.Json["instructedAmount"]?["currency"]?.GetValue<string>());
        Assert.Equal("500.00", detail.Json["instructedAmount"]?["amount"]?.GetValue<string>());
        Assert.Equal("DE02100100109307118603", detail.Json["creditorAccount"]?["iban"]?.GetValue<string>());
        Assert.IsType<JsonArray>(detail.Json["lineItems"]);
        Assert.Equal(2, detail.Json["lineItems"]?.AsArray().Count);
    }

    [Fact]
    public void Payload_AuthorizationDetails_ReadsArrayFromUnderlyingClaim()
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

        Assert.Equal(PaymentInitiationType, details[0].Type);
        Assert.Equal(new[] { InitiateAction }, details[0].Actions);
        Assert.Equal("500.00", details[0].Json["amount"]?.GetValue<string>());

        Assert.Equal("account_information", details[1].Type);
        Assert.Equal(new[] { "https://api.bank.example/accounts" }, details[1].Locations);
    }

    [Fact]
    public void Payload_AuthorizationDetails_SetterBuildsArrayFromWrappers()
    {
        var details = new[]
        {
            new AuthorizationDetail((JsonObject)JsonNode.Parse(
                """
                { "type": "payment_initiation", "actions": ["initiate"],
                  "instructedAmount": { "currency": "EUR", "amount": "500.00" } }
                """)!),
            new AuthorizationDetail(new JsonObject())
            {
                Type = "account_information",
                Locations = new[] { "https://api.bank.example/accounts" },
            },
        };

        var payload = new JsonWebTokenPayload(new JsonObject())
        {
            AuthorizationDetails = details,
        };

        Assert.IsType<JsonArray>(payload.Json[IanaClaimTypes.AuthorizationDetails]);

        var round = payload.AuthorizationDetails?.ToArray();

        Assert.NotNull(round);
        Assert.Equal(2, round.Length);
        Assert.Equal(PaymentInitiationType, round[0].Type);
        Assert.Equal(new[] { InitiateAction }, round[0].Actions);
        Assert.Equal("EUR", round[0].Json["instructedAmount"]?["currency"]?.GetValue<string>());
        Assert.Equal("account_information", round[1].Type);
        Assert.Equal(new[] { "https://api.bank.example/accounts" }, round[1].Locations);
    }

    [Fact]
    public void Payload_AuthorizationDetails_SetNullRemovesClaim()
    {
        var payload = new JsonWebTokenPayload(new JsonObject())
        {
            AuthorizationDetails = new[]
            {
                new AuthorizationDetail(new JsonObject()) { Type = "x" },
            },
        };
        Assert.True(payload.Json.ContainsKey(IanaClaimTypes.AuthorizationDetails));

        payload.AuthorizationDetails = null;

        Assert.False(payload.Json.ContainsKey(IanaClaimTypes.AuthorizationDetails));
        Assert.Null(payload.AuthorizationDetails);
    }

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
