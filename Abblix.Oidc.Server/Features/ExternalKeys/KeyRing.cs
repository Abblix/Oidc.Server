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

    /// <summary>
    /// One opened entry: the key itself, when it was minted, which is what orders the set, and the id it is
    /// stored under, which is what retires it.
    /// </summary>
    private sealed record OpenedKey(string Id, JsonWebKey Key, DateTimeOffset CreatedAt);

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
            opened.Add(new OpenedKey(entry.Id, key, entry.CreatedAt));
        }

        _keys = await RetireExpiredAsync(opened, cancellationToken);
    }

    /// <summary>
    /// Drops the keys whose last token has expired, and returns what remains.
    /// </summary>
    /// <remarks>
    /// Without this the ring only grows, and every refresh opens one more envelope, which is a custodian
    /// round-trip apiece.
    /// <para>
    /// A key retires when its successor starts signing, not when the successor appears, so the moment is derived
    /// rather than stored: the successor is active at its own creation plus the propagation window, and from then
    /// the retired key only has to outlive the tokens it already signed. Every pod computes the same instant from
    /// the same entries, so they need no agreement about it, and a removal race is harmless - two pods dropping
    /// the same expired key is the outcome either wanted.
    /// </para>
    /// </remarks>
    private async Task<IReadOnlyList<OpenedKey>> RetireExpiredAsync(
        IReadOnlyList<OpenedKey> opened,
        CancellationToken cancellationToken)
    {
        var now = timeProvider.GetUtcNow();
        var propagation = options.Value.KeyRolloverPropagation;
        var keepRetiredFor = policy.KeepRetiredFor ?? policy.RotateEvery;

        var live = new List<OpenedKey>(opened.Count);
        foreach (var group in opened.GroupBy(key => key.Key.Usage))
        {
            // Oldest first, so each key's successor is simply the next one along. The newest of a role has no
            // successor and therefore never retires: it is the key currently signing, or the one about to.
            var byOldest = group.OrderBy(key => key.CreatedAt).ToList();

            for (var index = 0; index < byOldest.Count; index++)
            {
                var key = byOldest[index];
                var successor = index + 1 < byOldest.Count ? byOldest[index + 1] : null;

                if (successor is null || now <= successor.CreatedAt + propagation + keepRetiredFor)
                {
                    live.Add(key);
                    continue;
                }

                await store.RemoveAsync(key.Id, cancellationToken);
            }
        }

        return live;
    }

    /// <summary>
    /// Mints the keys the current period lacks, and reports whether the ring changed.
    /// </summary>
    private async Task<bool> MintDueKeysAsync(IReadOnlyList<StoredKey> entries, CancellationToken cancellationToken)
    {
        var minted = false;

        foreach (var (usage, algorithm) in Roles())
        {
            var id = PeriodId(usage, algorithm);
            if (entries.Any(entry => entry.Id == id))
                continue;

            var jwe = await SealNewKeyAsync(usage, algorithm, cancellationToken);

            // Minted now, not at the start of the period. The period is a coordinate on the rotation grid and can
            // lie weeks in the past; dating the key by it would make it born already old, so the propagation
            // window would be long spent and it would start signing before any client could have fetched it.
            var entry = new StoredKey { Id = id, Jwe = jwe, CreatedAt = timeProvider.GetUtcNow() };

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
    /// It is floored to the rotation grid rather than read off the clock, which is the whole point: two pods
    /// minting seconds apart still compute one id and race for it, instead of each creating a key. This is a
    /// coordinate, not a timestamp - when a key was actually minted is recorded separately, since the period may
    /// have begun long before the pod got to it.
    /// </remarks>
    private string PeriodId(string usage, string algorithm)
    {
        var periods = timeProvider.GetUtcNow().UtcTicks / policy.RotateEvery.Ticks;
        var periodStart = new DateTimeOffset(periods * policy.RotateEvery.Ticks, TimeSpan.Zero);

        return $"{usage}-{algorithm}-{periodStart:yyyyMMddTHHmmssZ}";
    }
}
