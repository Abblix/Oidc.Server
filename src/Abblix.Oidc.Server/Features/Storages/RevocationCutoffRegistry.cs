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

    /// <summary>
    /// How many times a cutoff is read and written before recording it is given up as impossible.
    /// </summary>
    /// <remarks>
    /// Each attempt that fails means another caller wrote the same principal's record in between, and revocations of
    /// one principal arriving together are a handful at most. A storage that never reports a replace as made, against
    /// its contract, would otherwise keep the revoking call, and a thread, busy for good: a bound turns that into an
    /// error naming the cause.
    /// </remarks>
    private const int RecordingAttempts = 16;

    /// <inheritdoc />
    /// <remarks>
    /// Read, compare, and write only if nobody wrote in between, or read again: a plain write would let a call
    /// with an earlier cutoff that lands later, a retry or a slower concurrent call, move the record back. The
    /// expiry is kept the same way, the later of the two, so a revocation repeated later keeps the record longer
    /// even when its cutoff is not later.
    /// </remarks>
    public async Task SetCutoffAsync(
        RevocationScope scope,
        string principal,
        DateTimeOffset cutoff,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default)
    {
        var key = keyFactory.RevocationCutoffKey(scope, principal);

        for (var attempt = 0; attempt < RecordingAttempts; attempt++)
        {
            var stored = await storage.GetAsync<Proto.RevocationCutoff>(key, false, cancellationToken);
            if (stored is null)
            {
                if (await storage.TrySetIfAbsentAsync(key, Record(cutoff, expiresAt), Expiring(expiresAt), cancellationToken))
                    return;

                continue;
            }

            var keptCutoff = Later(stored.Cutoff, cutoff);
            var keptExpiry = Later(stored.ExpiresAt, expiresAt);
            if (keptCutoff == stored.Cutoff?.ToDateTimeOffset() && keptExpiry == stored.ExpiresAt?.ToDateTimeOffset())
                return;

            if (await storage.TryReplaceAsync(
                    key, stored, Record(keptCutoff, keptExpiry), Expiring(keptExpiry), cancellationToken))
                return;
        }

        throw new InvalidOperationException(
            $"The {scope} revocation cutoff could not be recorded: the storage reported its record changed on each " +
            $"of {RecordingAttempts} attempts, which a storage that never reports a replace as made also does");
    }

    /// <summary>
    /// The later of a recorded instant and a new one; an instant not recorded, as in a record from before the
    /// field existed, yields the new one.
    /// </summary>
    private static DateTimeOffset Later(Timestamp? recorded, DateTimeOffset given)
        => recorded?.ToDateTimeOffset() is { } instant && instant > given ? instant : given;

    private static Proto.RevocationCutoff Record(DateTimeOffset cutoff, DateTimeOffset expiresAt) => new()
    {
        Cutoff = Timestamp.FromDateTimeOffset(cutoff),
        ExpiresAt = Timestamp.FromDateTimeOffset(expiresAt),
    };

    private static StorageOptions Expiring(DateTimeOffset expiresAt) => new() { AbsoluteExpiration = expiresAt };
}
