// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Implementation;
using Abblix.Oidc.Server.Model;
using Xunit;
using RequestParameters = Abblix.Oidc.Server.Model.AuthorizationRequest.Parameters;

namespace Abblix.Oidc.Server.UnitTests.Common.Implementation;

/// <summary>
/// JAR (RFC 9101) merges a signed-JWT payload into the live AuthorizationRequest
/// via <see cref="JsonSerializationBinder"/>. These tests lock the contract that
/// the RFC 9396 <c>authorization_details</c> claim survives that merge - both as
/// a fresh value carried only in the JWT, and as an overwrite of a base-request
/// value.
/// </summary>
public class JsonSerializationBinderRarTests
{
    private const string WireJson =
        """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";

    [Fact]
    public async Task JsonSerializationBinder_projects_authorization_details_from_jwt_payload_onto_request()
    {
        var binder = new JsonSerializationBinder();
        var baseRequest = new AuthorizationRequest { ClientId = "client-123" };
        var jwtPayload = new JsonObject
        {
            ["authorization_details"] = JsonNode.Parse(WireJson),
        };

        var merged = await binder.BindModelAsync(jwtPayload, baseRequest);

        Assert.NotNull(merged);
        Assert.Equal("client-123", merged!.ClientId);
        Assert.NotNull(merged.AuthorizationDetails);
        Assert.Equal(WireJson, merged.AuthorizationDetails!.ToJsonString());
    }

    [Fact]
    public async Task JsonSerializationBinder_overwrites_request_authorization_details_with_jwt_payload_value()
    {
        var binder = new JsonSerializationBinder();
        var initialArray = (JsonArray)JsonNode.Parse(
            """[{"type":"account_information","identifier":"acct-001"}]""")!;
        var baseRequest = new AuthorizationRequest
        {
            ClientId = "client-123",
            AuthorizationDetails = initialArray,
        };
        var jwtPayload = new JsonObject
        {
            ["authorization_details"] = JsonNode.Parse(WireJson),
        };

        var merged = await binder.BindModelAsync(jwtPayload, baseRequest);

        Assert.NotNull(merged);
        // JAR is the integrity-protected source - JWT-side value wins over the
        // outer raw form parameter on conflict (RFC 9101 section 5).
        Assert.Equal(WireJson, merged!.AuthorizationDetails!.ToJsonString());
    }

    [Fact]
    public async Task JsonSerializationBinder_keeps_authorization_details_null_when_jwt_payload_omits_claim()
    {
        var binder = new JsonSerializationBinder();
        var baseRequest = new AuthorizationRequest { ClientId = "client-123" };
        var jwtPayload = new JsonObject
        {
            [RequestParameters.ClientId] = "client-123",
            [RequestParameters.State] = "abc",
        };

        var merged = await binder.BindModelAsync(jwtPayload, baseRequest);

        Assert.NotNull(merged);
        Assert.Null(merged!.AuthorizationDetails);
    }
}
