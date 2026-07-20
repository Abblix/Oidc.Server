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

using System.Globalization;
using System.Net;
using System.Text.Json;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.Vault;

/// <summary>
/// Keeps the key ring in a Vault / OpenBao KV version 2 engine, one secret per key.
/// </summary>
/// <remarks>
/// The whole reason this backend fits is one flag: a KV v2 write takes <c>cas</c>, and <c>cas=0</c> means "create
/// only if this path has never existed". That is the insert-if-absent the ring needs, done by the store itself,
/// so pods need no lock service and no leader election to agree on who mints a period.
/// <para>
/// What is stored is a JWE the server sealed to the custodian's key, so this engine holds ciphertext and never a
/// secret. Vault's own encryption of it is a second layer, not the one the design leans on.
/// </para>
/// </remarks>
internal sealed partial class KeyValueStore(
    ILogger<KeyValueStore> logger,
    IHttpClientFactory httpClientFactory,
    IOptions<VaultKeyValueOptions> options)
    : IKeyRingStore
{
    /// <summary>The shared client, held for this singleton's lifetime; see the custodian for why it is by name.</summary>
    private readonly HttpClient _httpClient = httpClientFactory.CreateClient(Transport.ClientName);

    private VaultKeyValueOptions Options => options.Value;

    /// <inheritdoc />
    public async Task<IReadOnlyList<StoredKey>> LoadAsync(CancellationToken cancellationToken)
    {
        var ids = await ListIdsAsync(cancellationToken);

        var entries = new List<StoredKey>(ids.Count);
        foreach (var id in ids)
        {
            if (await ReadAsync(id, cancellationToken) is { } entry)
                entries.Add(entry);
        }

        return entries;
    }

    /// <inheritdoc />
    public async Task<bool> TryAddAsync(StoredKey key, CancellationToken cancellationToken)
    {
        var body = new KeyValueRequest
        {
            // cas=0: create only if this path never existed. Two pods minting the same period both send this, and
            // Vault lets exactly one through.
            Options = new KeyValueRequest.CheckAndSet { Cas = 0 },
            Data = new KeyValueRequest.Entry { Jwe = key.Jwe, CreatedAt = key.CreatedAt.ToString("O") },
        };

        using var response = await _httpClient.SendAsync(HttpMethod.Post, DataPath(key.Id), body, cancellationToken);
        if (response.IsSuccess)
        {
            LogPeriodMinted(key.Id);
            return true;
        }

        // Vault answers a lost cas race with 400, which is also how it reports a malformed request, so the two
        // are told apart by the message rather than the status.
        if (response.Status == HttpStatusCode.BadRequest
            && response.Errors.Contains("check-and-set", StringComparison.OrdinalIgnoreCase))
        {
            return await LostRaceOrWedged(key.Id, cancellationToken);
        }

        throw response.Failure(DataPath(key.Id));
    }

    /// <summary>
    /// Disambiguates a cas=0 rejection, which has two causes that must not be conflated.
    /// </summary>
    /// <remarks>
    /// Usually another pod minted this period first: reading the entry back finds its key, and dropping the one
    /// generated here is routine. But cas=0 rejects any path that has ever held a version, and an operator's
    /// <c>vault kv delete</c> soft-deletes the latest version while leaving the metadata, so cas=0 keeps failing
    /// though the data reads as absent - the period could never be minted and would otherwise read as a race
    /// nobody wins. Reading the entry back tells the two apart, so the wedge fails loud instead of looping.
    /// </remarks>
    private async Task<bool> LostRaceOrWedged(string id, CancellationToken cancellationToken)
    {
        if (await ReadAsync(id, cancellationToken) is not null)
        {
            LogMintRaceLost(id);
            return false;
        }

        throw new InvalidOperationException(
            $"Vault KV '{DataPath(id)}' is wedged by a soft-deleted version: cas=0 cannot write over it, yet its " +
            "data reads as absent, so this period can never be minted. Destroy its metadata with " +
            $"`vault kv metadata delete {Options.Mount}/{Options.Path}/{id}` to clear it.");
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string id, CancellationToken cancellationToken)
    {
        // Removing the metadata drops the secret and every version of it, which is what retiring a key means
        // here. A 404 is success: the entry is gone, which is all the caller asked for.
        using var response = await _httpClient.SendAsync(
            HttpMethod.Delete, MetadataPath(id), body: null, cancellationToken);

        if (response.Status == HttpStatusCode.NotFound)
            return;

        response.EnsureSuccess(MetadataPath(id));
    }

    /// <summary>Lists the ring's secret names, tolerating a ring that does not exist yet.</summary>
    private async Task<IReadOnlyList<string>> ListIdsAsync(CancellationToken cancellationToken)
    {
        var path = $"{Options.Mount}/metadata/{Options.Path}";
        using var response = await _httpClient.SendAsync(new HttpMethod("LIST"), path, body: null, cancellationToken);

        // A ring nobody has minted into yet is not an error: the first pod to run is supposed to find it empty
        // and mint into it.
        if (response.Status == HttpStatusCode.NotFound)
            return [];

        response.EnsureSuccess(path);

        return response.Body(path).RootElement
            .GetProperty("data")
            .GetProperty("keys")
            .EnumerateArray()
            .Select(key => key.GetString()!)
            .ToList();
    }

    /// <summary>Reads one entry, tolerating one deleted between the listing and the read.</summary>
    private async Task<StoredKey?> ReadAsync(string id, CancellationToken cancellationToken)
    {
        using var response = await _httpClient.SendAsync(HttpMethod.Get, DataPath(id), body: null, cancellationToken);
        if (response.Status == HttpStatusCode.NotFound)
            return null;

        response.EnsureSuccess(DataPath(id));

        // KV v2 nests the entry one level down: the outer "data" is the response envelope, the inner one is what
        // was written.
        var entry = response.Body(DataPath(id)).RootElement.GetProperty("data").GetProperty("data")
            .Deserialize<KeyValueRequest.Entry>()
            ?? throw response.Failure(DataPath(id));

        return new StoredKey
        {
            Id = id,
            Jwe = entry.Jwe,

            // Written with "O", so read it back the same way: round-trip, culture-independent.
            CreatedAt = DateTimeOffset.Parse(
                entry.CreatedAt,
                CultureInfo.InvariantCulture,
                DateTimeStyles.RoundtripKind),
        };
    }

    private string DataPath(string id) => $"{Options.Mount}/data/{Options.Path}/{id}";

    private string MetadataPath(string id) => $"{Options.Mount}/metadata/{Options.Path}/{id}";
}
