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
using Abblix.Oidc.Server.Mvc.Model;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Model;

/// <summary>
/// Covers the MVC binding edge for RFC 9396 authorization_details on the
/// /authorize + /par endpoints (both routes share this single MVC model):
/// the binder must surface the raw JsonArray onto the model and the
/// Map() projection must hand it through to the core pipeline byte-exact.
/// </summary>
public class AuthorizationRequestBindingTests
{
    [Fact]
    public void Map_PropagatesAuthorizationDetails_ByteExact()
    {
        const string wireJson =
            """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";
        var bound = (JsonArray)JsonNode.Parse(wireJson)!;
        var mvcModel = new AuthorizationRequest { AuthorizationDetails = bound };

        var core = mvcModel.Map();

        Assert.NotNull(core.AuthorizationDetails);
        Assert.Equal(wireJson, core.AuthorizationDetails!.ToJsonString());
    }

    [Fact]
    public void Map_NullAuthorizationDetails_StaysNullOnCoreModel()
    {
        var mvcModel = new AuthorizationRequest();

        var core = mvcModel.Map();

        Assert.Null(core.AuthorizationDetails);
    }

    [Fact]
    public void SystemTextJson_DeserializesAuthorizationDetailsIntoJsonArray()
    {
        // Locks the assumption JsonSerializerModelBinder relies on: a wire
        // authorization_details parameter (a JSON array string after MVC
        // performs its own form/query decoding) round-trips byte-exact via
        // JsonSerializer.Deserialize<JsonArray> — preserving member order
        // and the type-specific extension payload that downstream protobuf
        // storage and JWT claim emission also preserve byte-exact.
        const string wireJson =
            """[{"type":"payment_initiation","actions":["initiate"],"locations":["https://api.bank.example"]},{"type":"account_information","identifier":"acct-001"}]""";

        var parsed = JsonSerializer.Deserialize<JsonArray>(wireJson);

        Assert.NotNull(parsed);
        Assert.Equal(wireJson, parsed!.ToJsonString());
    }
}
