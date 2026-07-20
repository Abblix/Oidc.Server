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

using System.Net;
using System.Text.Json;
using Abblix.Jwt.ExternalKeys;
using Azure;
using Azure.Storage.Blobs;
using Azure.Storage.Blobs.Models;
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Azure;

/// <summary>
/// Keeps the key ring in an Azure Blob Storage container, one blob per key.
/// </summary>
/// <remarks>
/// The backend is chosen for one primitive: an upload with <c>If-None-Match: *</c> succeeds only if the blob does
/// not exist, answering 409 otherwise. That is the ring's insert-if-absent, done by the store, so pods settle who
/// mints a period without a lock service or leader election.
/// <para>
/// A blob holds a JWE the server sealed to the vault's key, so the container holds ciphertext and never a secret.
/// Storage-side encryption is a second layer, not the one the design leans on.
/// </para>
/// </remarks>
internal sealed partial class BlobKeyRingStore(ILogger<BlobKeyRingStore> logger, BlobContainerClient container)
    : IKeyRingStore
{
    /// <inheritdoc />
    public async Task<IReadOnlyList<StoredKey>> LoadAsync(CancellationToken cancellationToken)
    {
        // A ring nobody has minted into yet is the normal bootstrap: the first pod is meant to find it empty.
        await container.CreateIfNotExistsAsync(cancellationToken: cancellationToken);

        var entries = new List<StoredKey>();
        await foreach (var blob in container.GetBlobsAsync(cancellationToken: cancellationToken))
        {
            if (await ReadAsync(blob.Name, cancellationToken) is { } entry)
                entries.Add(entry);
        }

        return entries;
    }

    /// <inheritdoc />
    public async Task<bool> TryAddAsync(StoredKey key, CancellationToken cancellationToken)
    {
        await container.CreateIfNotExistsAsync(cancellationToken: cancellationToken);

        var payload = JsonSerializer.SerializeToUtf8Bytes(new BlobEntry(key.Jwe, key.CreatedAt));
        using var content = new MemoryStream(payload, writable: false);

        try
        {
            // If-None-Match: * is the whole coordination: it uploads only when the blob is absent, so two pods
            // minting the same period cannot both win.
            await container.GetBlobClient(key.Id).UploadAsync(
                content,
                new BlobUploadOptions { Conditions = new BlobRequestConditions { IfNoneMatch = ETag.All } },
                cancellationToken);

            LogPeriodMinted(key.Id);
            return true;
        }
        catch (RequestFailedException failure)
            when (failure.Status == (int)HttpStatusCode.Conflict
                  && failure.ErrorCode == BlobErrorCode.BlobAlreadyExists)
        {
            // Another pod minted this period first. Its key is as good as ours, so the caller drops what it
            // generated rather than publishing a second key for the period.
            //
            // The error code, not the status alone: 409 also carries ContainerBeingDeleted, LeaseAlreadyPresent
            // and others. Reading those as "someone won" would make this pod discard a key nobody stored, and the
            // period would then have no key at all.
            LogMintRaceLost(key.Id);
            return false;
        }
    }

    /// <inheritdoc />
    public async Task RemoveAsync(string id, CancellationToken cancellationToken)
        => await container.GetBlobClient(id).DeleteIfExistsAsync(cancellationToken: cancellationToken);

    /// <summary>Reads one entry, tolerating one deleted between the listing and the read.</summary>
    private async Task<StoredKey?> ReadAsync(string id, CancellationToken cancellationToken)
    {
        try
        {
            var content = await container.GetBlobClient(id).DownloadContentAsync(cancellationToken);
            var entry = content.Value.Content.ToObjectFromJson<BlobEntry>()
                ?? throw new InvalidOperationException($"The key ring entry '{id}' holds no readable content.");

            return new StoredKey { Id = id, Jwe = entry.Jwe, CreatedAt = entry.CreatedAt };
        }
        catch (RequestFailedException failure) when (failure.Status == (int)HttpStatusCode.NotFound)
        {
            // Retired between the listing and this read, which is a race the caller does not care about: the key
            // is gone either way.
            return null;
        }
    }

    /// <summary>
    /// One ring entry as it sits in a blob: ciphertext and a timestamp. The store learns nothing about the key,
    /// and could not open it if it tried.
    /// </summary>
    private sealed record BlobEntry(string Jwe, DateTimeOffset CreatedAt);
}
