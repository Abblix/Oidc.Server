// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Google.Protobuf.WellKnownTypes;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Keeps the ended flows in the same entity storage the stored requests live in.
/// </summary>
/// <param name="storage">Where the record is written and read.</param>
/// <param name="keyFactory">Names the record.</param>
/// <param name="timeProvider">Dates the record.</param>
public class ConsumedRequestUriRegistry(
    IEntityStorage storage,
    IEntityStorageKeyFactory keyFactory,
    TimeProvider timeProvider) : IConsumedRequestUriRegistry
{
    /// <inheritdoc />
    public Task MarkConsumedAsync(Uri requestUri, DateTimeOffset expiresAt)
        => storage.SetAsync(
            keyFactory.ConsumedRequestUriKey(requestUri),
            new Proto.ConsumedRequestUri { ConsumedAt = Timestamp.FromDateTimeOffset(timeProvider.GetUtcNow()) },
            new StorageOptions { AbsoluteExpiration = expiresAt });

    /// <inheritdoc />
    public async Task<bool> IsConsumedAsync(Uri requestUri)
        => await storage.GetAsync<Proto.ConsumedRequestUri>(keyFactory.ConsumedRequestUriKey(requestUri), false)
            is not null;
}
