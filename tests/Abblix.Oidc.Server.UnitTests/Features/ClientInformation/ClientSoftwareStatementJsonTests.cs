// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.ClientInformation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// The software statement a client record carries, as a host's store keeps it in JSON. A record naming none is a
/// client registered without one, as every record written before the member existed is; one naming a statement is read
/// with it, and the statement survives the round trip unmodified.
/// </summary>
public class ClientSoftwareStatementJsonTests
{
    private const string Statement = "eyJhbGciOiJSUzI1NiJ9.eyJyZWRpcmVjdF91cmlzIjpbXX0.c2lnbmF0dXJl";

    [Fact]
    public void ARecordNamingNoStatement_HasNone()
    {
        var json = new JsonObject { [nameof(ClientInfo.ClientId)] = "client-1" };

        Assert.Null(JsonSerializer.Deserialize<ClientInfo>(json.ToJsonString())!.SoftwareStatement);
    }

    [Fact]
    public void ARecordNamingAStatement_IsReadWithIt()
    {
        var json = new JsonObject
        {
            [nameof(ClientInfo.ClientId)] = "client-1",
            [nameof(ClientInfo.SoftwareStatement)] = Statement,
        };

        Assert.Equal(Statement, JsonSerializer.Deserialize<ClientInfo>(json.ToJsonString())!.SoftwareStatement);
    }

    [Fact]
    public void TheStatement_SurvivesTheRoundTripUnmodified()
    {
        var written = JsonSerializer.Serialize(new ClientInfo("client-1") { SoftwareStatement = Statement });

        Assert.Equal(Statement, JsonDocument.Parse(written).RootElement.GetProperty(nameof(ClientInfo.SoftwareStatement)).GetString());
        Assert.Equal(Statement, JsonSerializer.Deserialize<ClientInfo>(written)!.SoftwareStatement);
    }
}
