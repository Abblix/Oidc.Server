// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Generic;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Features.ClientInformation;
using Microsoft.Extensions.Configuration;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// The trust a client record carries, as a host's store keeps it in JSON and as the host declares it in its settings.
/// A record naming none is reviewed, as every client of a record written before the member existed was; one naming a
/// value is read as named; a null in its place is refused.
/// </summary>
public class ClientTrustJsonTests
{
    [Fact]
    public void ARecordNamingNoTrust_IsReviewed()
    {
        var json = new JsonObject { [nameof(ClientInfo.ClientId)] = "client-1" };

        Assert.Equal(ClientTrust.Reviewed, JsonSerializer.Deserialize<ClientInfo>(json.ToJsonString())!.Trust);
    }

    [Theory]
    [InlineData("reviewed", ClientTrust.Reviewed)]
    [InlineData("unreviewed", ClientTrust.Unreviewed)]
    public void ARecordNamingATrust_IsReadAsNamed(string written, ClientTrust trust)
    {
        var json = new JsonObject
        {
            [nameof(ClientInfo.ClientId)] = "client-1",
            [nameof(ClientInfo.Trust)] = written,
        };

        Assert.Equal(trust, JsonSerializer.Deserialize<ClientInfo>(json.ToJsonString())!.Trust);
    }

    [Fact]
    public void ARecordHoldingANullTrust_IsRefused()
    {
        var json = new JsonObject
        {
            [nameof(ClientInfo.ClientId)] = "client-1",
            [nameof(ClientInfo.Trust)] = null,
        };

        Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<ClientInfo>(json.ToJsonString()));
    }

    [Theory]
    [InlineData(ClientTrust.Reviewed)]
    [InlineData(ClientTrust.Unreviewed)]
    public void TheTrust_SurvivesTheRoundTripAsAString(ClientTrust trust)
    {
        var written = JsonSerializer.Serialize(new ClientInfo("client-1") { Trust = trust });

        Assert.Equal(JsonValueKind.String, JsonDocument.Parse(written).RootElement.GetProperty(nameof(ClientInfo.Trust)).ValueKind);
        Assert.Equal(trust, JsonSerializer.Deserialize<ClientInfo>(written)!.Trust);
    }

    /// <summary>
    /// A client the host declares in its settings is reviewed unless the host says otherwise there.
    /// </summary>
    [Theory]
    [InlineData(null, ClientTrust.Reviewed)]
    [InlineData("Unreviewed", ClientTrust.Unreviewed)]
    public void AClientTheSettingsDeclare_IsReviewedUnlessTheySayOtherwise(string? written, ClientTrust trust)
    {
        var values = new Dictionary<string, string?> { [nameof(ClientInfo.ClientId)] = "client-1" };
        if (written != null)
            values[nameof(ClientInfo.Trust)] = written;
        var settings = new ConfigurationBuilder().AddInMemoryCollection(values).Build();

        var client = new ClientInfo("client-1");
        settings.Bind(client);

        Assert.Equal(trust, client.Trust);
    }
}
