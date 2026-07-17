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

using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// The server's own key set: it mints keys on the rotation grid, seals them to the custodian's key-encryption
/// key, shares them through <see cref="IKeyRingStore"/>, and keeps the opened keys in memory for signing.
/// </summary>
/// <remarks>
/// Holding the opened keys is not an optimisation here, it is the tier: if the ring opened an envelope per token
/// the custodian would be on the hot path and this tier would be slower than the one where the key never leaves
/// the custodian at all. The custodian is touched once per key, at refresh.
/// <para>
/// Nothing about a key's state is stored. Given the entries and their creation times every pod computes the same
/// answer, so pods need no agreement to converge - only to avoid minting the same period twice, which the store's
/// insert-if-absent settles.
/// </para>
/// </remarks>
internal sealed class KeyRing(
    IKeyRingStore store,
    IKeyCustodian custodian,
    KeyEnvelope envelope,
    MintedKeys policy,
    IOptions<OidcOptions> options,
    TimeProvider timeProvider)
{
    private volatile IReadOnlyList<OpenedKey> _keys = [];

    /// <summary>One opened entry: the key itself, and when it was minted, which is what orders the set.</summary>
    private sealed record OpenedKey(JsonWebKey Key, DateTimeOffset CreatedAt);

    /// <summary>
    /// Returns the keys for a role, produce-first: the active one leads and the rest trail, so the produce role
    /// takes the active key while every key stays published for consumers.
    /// </summary>
    /// <param name="usage">Which role to serve, signature or encryption.</param>
    /// <param name="includePrivateKeys">Whether the caller needs the private half, which only signing and
    /// decryption do. Publication must not.</param>
    public IEnumerable<JsonWebKey> Get(string usage, bool includePrivateKeys)
        => _keys
            .Where(opened => opened.Key.Usage == usage)
            .ToList()
            .ProduceFirst(opened => opened.CreatedAt, timeProvider.GetUtcNow(), options.Value.KeyRolloverPropagation)
            .Select(opened => opened.Key.Sanitize(includePrivateKeys));

    /// <summary>
    /// Mints whatever the current period is missing, then reloads and opens the ring into memory.
    /// </summary>
    /// <param name="cancellationToken">Cancels the refresh.</param>
    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        var entries = await store.LoadAsync(cancellationToken);

        if (await MintDueKeysAsync(entries, cancellationToken))
        {
            // Something was minted, by this pod or by another that won the race: re-read so the ring holds the
            // winner's key rather than the one generated here.
            entries = await store.LoadAsync(cancellationToken);
        }

        var kekVersions = KekVersions(cancellationToken);
        var opened = new List<OpenedKey>(entries.Count);
        foreach (var entry in entries)
        {
            var key = await envelope.OpenAsync(entry.Jwe, kekVersions, cancellationToken);
            opened.Add(new OpenedKey(key, entry.CreatedAt));
        }

        _keys = opened;
    }

    /// <summary>
    /// Mints the keys the current period lacks, and reports whether the ring changed.
    /// </summary>
    private async Task<bool> MintDueKeysAsync(IReadOnlyList<StoredKey> entries, CancellationToken cancellationToken)
    {
        var minted = false;

        foreach (var (usage, algorithm) in Roles())
        {
            var id = PeriodId(usage, algorithm, out var periodStart);
            if (entries.Any(entry => entry.Id == id))
                continue;

            var jwe = await SealNewKeyAsync(usage, algorithm, cancellationToken);
            var entry = new StoredKey { Id = id, Jwe = jwe, CreatedAt = periodStart };

            // False means another pod claimed this period first. Its key is as good as ours, and the ring must
            // hold exactly one, so the loser simply drops what it generated. Nothing is retried.
            minted |= await store.TryAddAsync(entry, cancellationToken);
        }

        return minted;
    }

    /// <summary>Generates a key for the role and seals it to the newest KEK version.</summary>
    private async Task<string> SealNewKeyAsync(string usage, string algorithm, CancellationToken cancellationToken)
    {
        var key = JsonWebKeyFactory.CreateRsa(usage, algorithm, policy.RsaKeySize);
        var kek = await NewestKekAsync(cancellationToken);

        return await envelope.SealAsync(
            key, kek, policy.KeyWrapAlgorithm, policy.ContentEncryptionAlgorithm, cancellationToken);
    }

    /// <summary>
    /// The KEK version to seal with: the newest one. A KEK needs no propagation window, unlike a signing key,
    /// because it has no external consumer waiting to learn it - every reader of an envelope is this server.
    /// </summary>
    private async Task<JsonWebKey> NewestKekAsync(CancellationToken cancellationToken)
    {
        var versions = await custodian
            .GetKeyVersionsAsync(policy.KekName, cancellationToken)
            .ToListAsync(cancellationToken);

        if (versions.Count == 0)
        {
            throw new InvalidOperationException(
                $"The custodian holds no key named '{policy.KekName}', so nothing can seal a minted key.");
        }

        var newest = versions.MaxBy(version => version.CreatedAt).PublicKey;
        if (!newest.HasPublicKey)
        {
            throw new InvalidOperationException(
                $"The KEK '{policy.KekName}' must be an asymmetric key: sealing uses its public half in process, " +
                "and a symmetric key has none.");
        }

        return newest;
    }

    /// <summary>The KEK's versions, public half only, which is what routes an unwrap to the custodian.</summary>
    private IAsyncEnumerable<JsonWebKey> KekVersions(CancellationToken cancellationToken)
        => custodian.GetKeyVersionsAsync(policy.KekName, cancellationToken).Select(version => version.PublicKey);

    /// <summary>The roles this policy mints for: always signing, and encryption only when asked for.</summary>
    private IEnumerable<(string Usage, string Algorithm)> Roles()
    {
        yield return (PublicKeyUsages.Signature, policy.SigningAlgorithm);

        if (policy.EncryptionAlgorithm is { } encryption)
            yield return (PublicKeyUsages.Encryption, encryption);
    }

    /// <summary>
    /// The id every pod computes identically for the current period, which is what makes exactly one insert win.
    /// </summary>
    /// <remarks>
    /// The period start is floored to the rotation grid rather than read off the clock, so two pods minting
    /// seconds apart still race for one id instead of creating two keys.
    /// </remarks>
    private string PeriodId(string usage, string algorithm, out DateTimeOffset periodStart)
    {
        var now = timeProvider.GetUtcNow();
        var periods = now.UtcTicks / policy.RotateEvery.Ticks;
        periodStart = new DateTimeOffset(periods * policy.RotateEvery.Ticks, TimeSpan.Zero);

        return $"{usage}-{algorithm}-{periodStart:yyyyMMddTHHmmssZ}";
    }
}
