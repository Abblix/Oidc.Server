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
    /// <remarks>
    /// Read, compare, and write only if nobody wrote in between, or read again: a write of its own would let a
    /// call with an earlier cutoff that lands later, a retry or a slower concurrent call, move the record back.
    /// The record's expiry follows the cutoff it holds, so a cutoff left in place keeps its own.
    /// </remarks>
    public async Task SetCutoffAsync(
        RevocationScope scope,
        string principal,
        DateTimeOffset cutoff,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        var key = keyFactory.RevocationCutoffKey(scope, principal);
        var record = new Proto.RevocationCutoff { Cutoff = Timestamp.FromDateTimeOffset(cutoff) };
        var options = new StorageOptions { AbsoluteExpiration = expiresAt };

        while (true)
        {
            var stored = await storage.GetAsync<Proto.RevocationCutoff>(key, false, cancellationToken);
            if (stored is null)
            {
                if (await storage.TrySetIfAbsentAsync(key, record, options, cancellationToken))
                    return;

                continue;
            }

            if (stored.Cutoff is { } recorded && cutoff <= recorded.ToDateTimeOffset())
                return;

            if (await storage.TryReplaceAsync(key, stored, record, options, cancellationToken))
                return;
        }
    }
}
