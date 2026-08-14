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

using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The server's own key set: it mints keys on the rotation grid, seals them to the custodian's key-encryption
/// key, shares them through <see cref="IKeyRingStore"/>, and keeps the opened keys in memory for signing.
/// </summary>
/// <remarks>
/// Holding the opened keys is not an optimisation here, it is the placement: if the ring opened an envelope per token
/// the custodian would be on the hot path and this placement would be slower than the one where the key never leaves
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
    IOptions<KeyRingOptions> options,
    TimeProvider timeProvider)
    : IKeyRing
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
            .Where(opened => Serves(opened.Key, usage))
            .ToList()
            .ProduceFirst(opened => opened.CreatedAt, timeProvider.GetUtcNow(), options.Value.KeyRolloverPropagation)
            .Select(opened => opened.Key.Sanitize(includePrivateKeys));

    /// <summary>
    /// Whether a key may serve a role: either it names that role, or it names none and is therefore unrestricted.
    /// </summary>
    /// <remarks>
    /// RFC 7517 section 4.2 makes <c>use</c> OPTIONAL and single-valued, so a key permitted to both sign and
    /// encrypt is expressed by omitting the member, never by a multi-valued one. Reading an absent <c>use</c> as
    /// "no role" rather than "any role" would drop exactly those keys, and silently: they match no role, so they
    /// leave the published set without anything reporting a loss. A certificate permitting both signing and
    /// encipherment produces precisely such a key.
    /// </remarks>
    private static bool Serves(JsonWebKey key, string usage) => key.Usage is null || key.Usage == usage;

    /// <summary>
    /// Mints whatever the current period is missing, then reloads and opens the ring into memory.
    /// </summary>
    /// <param name="cancellationToken">Cancels the refresh.</param>
    public async Task RefreshAsync(CancellationToken cancellationToken)
    {
        var entries = await store.LoadAsync(cancellationToken);

        // Adoption first, and in the same refresh as the first mint: the adopted key is dated a period back, so
        // the key minted below trails it rather than taking over the instant it appears.
        var adopted = await AdoptExistingKeysAsync(entries, cancellationToken);

        if (await MintDueKeysAsync(entries, cancellationToken) || adopted)
        {
            // Something was written, by this pod or by another that won the race: re-read so the ring holds the
            // winner's key rather than the one generated here.
            entries = await store.LoadAsync(cancellationToken);
        }

        var versions = await KeyEncryptionKeyVersions(cancellationToken)
            .ToArrayAsync(cancellationToken: cancellationToken);

        var opened = new List<OpenedKey>(entries.Count);
        foreach (var entry in entries)
        {
            var key = await envelope.OpenAsync(entry.Jwe, versions.ToAsyncEnumerable(), cancellationToken);
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

        // Retirement is decided per ROLE, and a key is kept if any role it serves still needs it. That is what
        // makes an unrestricted key (no `use`, so it serves both) safe to hold: it leaves only once BOTH roles
        // have moved on, and a role nobody mints for - encryption, when no encryption algorithm is named - keeps
        // it indefinitely, which is correct, since it is the only key that role has.
        var expired = new HashSet<string>(opened.Select(key => key.Id));

        foreach (var usage in new[] { PublicKeyUsages.Signature, PublicKeyUsages.Encryption })
        {
            // Oldest first, so each key's successor is simply the next one along. The newest serving a role has
            // no successor and therefore never retires: it is the key currently producing, or the one about to.
            var byOldest = opened
                .Where(key => Serves(key.Key, usage))
                .OrderBy(key => key.CreatedAt)
                .ToList();

            for (var index = 0; index < byOldest.Count; index++)
            {
                var key = byOldest[index];
                var successor = index + 1 < byOldest.Count ? byOldest[index + 1] : null;

                if (successor is null || now <= successor.CreatedAt + propagation + keepRetiredFor)
                    expired.Remove(key.Id);
            }
        }

        var live = new List<OpenedKey>(opened.Count);
        foreach (var key in opened)
        {
            if (!expired.Contains(key.Id))
            {
                live.Add(key);
                continue;
            }

            await store.RemoveAsync(key.Id, cancellationToken);
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

    /// <summary>
    /// Takes the keys the server already signs with into an empty ring, and reports whether anything was written.
    /// </summary>
    /// <remarks>
    /// Only into an EMPTY ring, which is what lets the call stay in a host's registration forever: the moment the
    /// ring holds anything, adoption is over. A key that has since retired is therefore not brought back, and the
    /// ring cannot empty itself to make it look otherwise - the newest key serving a role never retires.
    /// <para>
    /// The entry is named after the key's own thumbprint (RFC 7638), so every pod computes the same id for the
    /// same key and the store's insert-if-absent settles the race exactly as it does for minting. The id also
    /// cannot collide with a period id, which is built from a role and an instant.
    /// </para>
    /// </remarks>
    private async Task<bool> AdoptExistingKeysAsync(
        IReadOnlyList<StoredKey> entries,
        CancellationToken cancellationToken)
    {
        if (entries.Count > 0 || policy.AdoptedKeys.Count == 0)
            return false;

        // Dated one rotation period back, which is what makes it the active key: the key minted in this same
        // refresh is younger than the propagation window, so it is published and verifiable while this one keeps
        // producing, and it takes over once the window has passed.
        var createdAt = timeProvider.GetUtcNow() - policy.RotateEvery;
        var keyEncryptionKey = await NewestKeyEncryptionKeyAsync(cancellationToken);
        var adopted = false;

        foreach (var key in policy.AdoptedKeys)
        {
            if (!key.HasPrivateKey)
            {
                throw new InvalidOperationException(
                    $"The key '{key.KeyId}' has no private half, so it cannot be adopted: an adopted key is the " +
                    "one that produces until the minted key's propagation window has passed, and producing needs " +
                    "the private half. Pass the key as it is loaded from its certificate or store.");
            }

            var entry = new StoredKey
            {
                Id = $"adopted-{key.ComputeJwkThumbprintBase64Url()}",
                Jwe = await SealAsync(key, keyEncryptionKey, cancellationToken),
                CreatedAt = createdAt,
            };

            adopted |= await store.TryAddAsync(entry, cancellationToken);
        }

        return adopted;
    }

    /// <summary>Generates a key for the role and seals it to the newest KEK version.</summary>
    private async Task<string> SealNewKeyAsync(string usage, string algorithm, CancellationToken cancellationToken)
    {
        var key = JsonWebKeyFactory.CreateRsa(usage, algorithm, policy.RsaKeySize);
        var keyEncryptionKey = await NewestKeyEncryptionKeyAsync(cancellationToken);

        return await SealAsync(key, keyEncryptionKey, cancellationToken);
    }

    /// <summary>Seals a key to the given KEK version, which is what the ring stores.</summary>
    private Task<string> SealAsync(JsonWebKey key, JsonWebKey keyEncryptionKey, CancellationToken cancellationToken)
        => envelope.SealAsync(
            key, keyEncryptionKey, policy.KeyWrapAlgorithm, policy.ContentEncryptionAlgorithm, cancellationToken);

    /// <summary>
    /// The KEK version to seal with: the newest one. A KEK needs no propagation window, unlike a signing key,
    /// because it has no external consumer waiting to learn it - every reader of an envelope is this server.
    /// </summary>
    private async Task<JsonWebKey> NewestKeyEncryptionKeyAsync(CancellationToken cancellationToken)
    {
        var versions = await custodian
            .GetKeyVersionsAsync(policy.KeyEncryptionKeyName, cancellationToken)
            .ToListAsync(cancellationToken);

        if (versions.Count == 0)
        {
            throw new InvalidOperationException(
                $"The custodian holds no key named '{policy.KeyEncryptionKeyName}', so nothing can seal a minted key.");
        }

        var newest = versions.MaxBy(version => version.CreatedAt).PublicKey;
        if (!newest.HasPublicKey)
        {
            throw new InvalidOperationException(
                $"The key-encryption key '{policy.KeyEncryptionKeyName}' must be asymmetric: sealing uses its " +
                "public half in process, and a symmetric key has none.");
        }

        return newest;
    }

    /// <summary>
    /// The key-encryption key's versions, public half only, which is what routes an unwrap to the custodian.
    /// </summary>
    private IAsyncEnumerable<JsonWebKey> KeyEncryptionKeyVersions(CancellationToken cancellationToken)
        => custodian
            .GetKeyVersionsAsync(policy.KeyEncryptionKeyName, cancellationToken)
            .Select(version => version.PublicKey);

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
