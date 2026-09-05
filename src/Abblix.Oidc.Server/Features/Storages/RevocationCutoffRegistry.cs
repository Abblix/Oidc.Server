// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Tokens.Revocation;

using Google.Protobuf.WellKnownTypes;

namespace Abblix.Oidc.Server.Features.Storages;

/// <summary>
/// Keeps revocation cutoffs in the same entity storage the rest of the server's short-lived state lives in.
/// </summary>
/// <param name="storage">Where the cutoff is written and read.</param>
/// <param name="keyFactory">Names the entry, so a deployment sharing one store across products keeps its
/// own namespace.</param>
public class RevocationCutoffRegistry(IEntityStorage storage, IEntityStorageKeyFactory keyFactory)
    : IRevocationCutoffRegistry
{
    /// <inheritdoc />
    public async Task<DateTimeOffset?> GetCutoffAsync(
        RevocationScope scope,
        string principal,
        CancellationToken cancellationToken = default)
    {
        var record = await storage.GetAsync<Proto.RevocationCutoff>(
            keyFactory.RevocationCutoffKey(scope, principal),
            false,
            cancellationToken);

        return record?.Cutoff?.ToDateTimeOffset();
    }

    /// <inheritdoc />
    public Task SetCutoffAsync(
        RevocationScope scope,
        string principal,
        DateTimeOffset cutoff,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
        => storage.SetAsync(
            keyFactory.RevocationCutoffKey(scope, principal),
            new Proto.RevocationCutoff { Cutoff = Timestamp.FromDateTimeOffset(cutoff) },
            new StorageOptions { AbsoluteExpiration = expiresAt },
            cancellationToken);
}
