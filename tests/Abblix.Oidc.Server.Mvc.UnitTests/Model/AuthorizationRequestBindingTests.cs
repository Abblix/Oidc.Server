// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Mvc.Model;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.UnitTests.Model;

/// <summary>
/// Covers the MVC binding edge for RFC 9396 authorization_details on the
/// /authorize + /par endpoints (both routes share this single MVC model):
/// the binder must surface the raw JsonArray onto the model and the
/// implicit projection must hand it through to the core pipeline byte-exact.
/// </summary>
public class AuthorizationRequestBindingTests
{
    [Fact]
    public void ImplicitProjection_PropagatesAuthorizationDetails_ByteExact()
    {
        const string wireJson =
            """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";
        var bound = (JsonArray)JsonNode.Parse(wireJson)!;
        var mvcModel = new AuthorizationRequest { AuthorizationDetails = bound };

        Core.AuthorizationRequest core = mvcModel;

        Assert.NotNull(core.AuthorizationDetails);
        Assert.Equal(wireJson, core.AuthorizationDetails!.ToJsonString());
    }

    [Fact]
    public void ImplicitProjection_NullAuthorizationDetails_StaysNullOnCoreModel()
    {
        var mvcModel = new AuthorizationRequest();

        Core.AuthorizationRequest core = mvcModel;

        Assert.Null(core.AuthorizationDetails);
    }

    [Fact]
    public void SystemTextJson_DeserializesAuthorizationDetailsIntoJsonArray()
    {
        // Locks the assumption JsonSerializerModelBinder relies on: a wire
        // authorization_details parameter (a JSON array string after MVC
        // performs its own form/query decoding) round-trips byte-exact via
        // JsonSerializer.Deserialize<JsonArray> - preserving member order
        // and the type-specific extension payload that downstream protobuf
        // storage and JWT claim emission also preserve byte-exact.
        const string wireJson =
            """[{"type":"payment_initiation","actions":["initiate"],"locations":["https://api.bank.example"]},{"type":"account_information","identifier":"acct-001"}]""";

        var parsed = JsonSerializer.Deserialize<JsonArray>(wireJson);

        Assert.NotNull(parsed);
        Assert.Equal(wireJson, parsed!.ToJsonString());
    }
}
