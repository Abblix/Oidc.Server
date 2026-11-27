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
/// Whether a client came from its metadata document is the server's to say: a stored client, as a host's store keeps
/// it in JSON, neither carries it nor brings it back.
/// </summary>
public class ResolvedFromMetadataDocumentJsonTests
{
    [Fact]
    public void Serialize_LeavesItOut()
    {
        var client = new ClientInfo("https://app.example.com/client.json") { ResolvedFromMetadataDocument = true };

        var json = JsonNode.Parse(JsonSerializer.Serialize(client))!.AsObject();

        Assert.False(json.ContainsKey(nameof(ClientInfo.ResolvedFromMetadataDocument)));
    }

    /// <summary>
    /// The setter is the server's alone, so a stored record naming the member true reads back as not resolved.
    /// </summary>
    [Fact]
    public void Deserialize_IgnoresIt()
    {
        var json = new JsonObject
        {
            [nameof(ClientInfo.ClientId)] = "https://app.example.com/client.json",
            [nameof(ClientInfo.ResolvedFromMetadataDocument)] = true,
        };

        var client = JsonSerializer.Deserialize<ClientInfo>(json.ToJsonString())!;

        Assert.False(client.ResolvedFromMetadataDocument);
    }
}
