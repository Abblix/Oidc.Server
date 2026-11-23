// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using System.Text.Json;
using Abblix.Oidc.Server.Features.ClientInformation;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientInformation;

/// <summary>
/// A host that keeps its clients as JSON must find each hash written once and the stored value in force.
/// The string aliases exist for the configuration binder; written into JSON as well, they repeat every hash
/// and, being read after the hash itself, overwrite whatever an operator edited there.
/// </summary>
public class ClientSecretJsonTests
{
    private static readonly byte[] Original = [0x2b, 0xb8, 0x0d, 0x53];
    private const string OriginalBase64 = "K7gNUw==";
    private const string OriginalHex = "2BB80D53";

    private static readonly byte[] Edited = [0x01, 0x02, 0x03, 0x04];
    private const string EditedBase64 = "AQIDBA==";

    [Fact]
    public void Serialize_WritesEachHashOnce()
    {
        var secret = new ClientSecret { Sha256Hash = Original, Sha512Hash = Original };

        using var json = JsonDocument.Parse(JsonSerializer.Serialize(secret));

        var names = json.RootElement.EnumerateObject().Select(property => property.Name).ToArray();
        Assert.Equal(
            [
                nameof(ClientSecret.Sha256Hash),
                nameof(ClientSecret.Sha512Hash),
                nameof(ClientSecret.Value),
                nameof(ClientSecret.EncryptedValue),
                nameof(ClientSecret.ExpiresAt),
            ],
            names);
    }

    [Fact]
    public void Serialize_ClientInfo_WritesEachSecretHashOnce()
    {
        var client = new ClientInfo("storefront")
        {
            ClientSecrets = [new ClientSecret { Sha512Hash = Original }],
        };

        using var json = JsonDocument.Parse(JsonSerializer.Serialize(client));

        var secret = Assert.Single(json.RootElement.GetProperty(nameof(ClientInfo.ClientSecrets)).EnumerateArray());
        var names = secret.EnumerateObject().Select(property => property.Name).ToArray();
        Assert.Contains(nameof(ClientSecret.Sha512Hash), names);
        Assert.DoesNotContain(nameof(ClientSecret.Sha512HashBase64), names);
        Assert.DoesNotContain(nameof(ClientSecret.Sha512HashHex), names);
    }

    [Fact]
    public void RoundTrip_KeepsBothHashes()
    {
        var secret = new ClientSecret { Sha256Hash = Original, Sha512Hash = Edited };

        var read = JsonSerializer.Deserialize<ClientSecret>(JsonSerializer.Serialize(secret));

        Assert.NotNull(read);
        Assert.Equal(Original, read.Sha256Hash);
        Assert.Equal(Edited, read.Sha512Hash);
    }

    /// <summary>
    /// JSON a host stored before the fix still carries the stale aliases next to the hash it edited.
    /// The edited hash is the one in force.
    /// </summary>
    [Fact]
    public void Deserialize_EditedHashBesideStaleAliases_KeepsTheEditedHash()
    {
        var json = $$"""
            {
              "Sha256Hash": null,
              "Sha512Hash": "{{EditedBase64}}",
              "Sha256HashBase64": null,
              "Sha512HashBase64": "{{OriginalBase64}}",
              "Sha256HashHex": null,
              "Sha512HashHex": "{{OriginalHex}}",
              "Value": null,
              "ExpiresAt": null
            }
            """;

        var read = JsonSerializer.Deserialize<ClientSecret>(json);

        Assert.NotNull(read);
        Assert.Equal(Edited, read.Sha512Hash);
    }

    /// <summary>
    /// JSON written by the previous release, every hash in three forms that agree, reads to the same hashes.
    /// </summary>
    [Fact]
    public void Deserialize_ThreeFormJsonFromEarlierRelease_ReadsTheSameHashes()
    {
        var json = $$"""
            {
              "Sha256Hash": "{{OriginalBase64}}",
              "Sha512Hash": "{{OriginalBase64}}",
              "Sha256HashBase64": "{{OriginalBase64}}",
              "Sha512HashBase64": "{{OriginalBase64}}",
              "Sha256HashHex": "{{OriginalHex}}",
              "Sha512HashHex": "{{OriginalHex}}",
              "Value": null,
              "ExpiresAt": null
            }
            """;

        var read = JsonSerializer.Deserialize<ClientSecret>(json);

        Assert.NotNull(read);
        Assert.Equal(Original, read.Sha256Hash);
        Assert.Equal(Original, read.Sha512Hash);
    }
}
