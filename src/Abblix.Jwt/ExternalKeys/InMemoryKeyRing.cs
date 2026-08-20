// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// A key ring whose keys are minted in this process and never leave it.
/// </summary>
/// <remarks>
/// The default for a host that has no HSM or KMS, which is most of them. It gives what a ring is for -
/// rotation without breaking what the retired key produced - and nothing more: the keys live in memory, so
/// they are gone when the process is, and no other process shares them.
///
/// That last property is the whole of the difference from <see cref="KeyRing"/>, and it is a difference in
/// guarantee, not in strength. A custodian-backed ring puts the private half somewhere this process cannot
/// reach and every replica can; this one puts it somewhere only this process can reach. Which is right
/// depends on how the host is deployed, so the host chooses rather than inheriting a default.
/// </remarks>
public sealed class InMemoryKeyRing : IKeyRing
{
    private readonly LocalKeys _policy;
    private readonly KeyRingOptions _options;
    private readonly TimeProvider _timeProvider;

    /// <summary>
    /// The minted keys with the moment each was made, which is what decides producing order and retirement.
    /// </summary>
    private readonly List<MintedKey> _keys = [];

    /// <summary>
    /// Guards minting and retirement. Reads take it too: a caller must not observe the list mid-rotation, with
    /// the retired key already gone and its replacement not yet added.
    /// </summary>
    private readonly Lock _gate = new();

    /// <summary>
    /// Creates the ring.
    /// </summary>
    public InMemoryKeyRing(LocalKeys policy, IOptions<KeyRingOptions> options, TimeProvider timeProvider)
    {
        _policy = policy;
        _options = options.Value;
        _timeProvider = timeProvider;
    }

    /// <inheritdoc />
    public IEnumerable<JsonWebKey> Get(string usage, bool includePrivateKeys)
    {
        using (_gate.EnterScope())
        {
            // Minting here rather than only in RefreshAsync so a ring that is asked before its first refresh
            // answers with a key instead of an empty set. A host without the refresh service running at all
            // still gets a working ring, it simply never rotates.
            MintDue();
            RetireExpired();

            return _keys
                .Where(minted => minted.Key.Usage == usage)
                .ToList()
                .ProduceFirst(minted => minted.CreatedAt, _timeProvider.GetUtcNow(), _options.KeyRolloverPropagation)
                .Select(minted => minted.Key.Sanitize(includePrivateKeys))
                .ToList();
        }
    }

    /// <inheritdoc />
    public Task RefreshAsync(CancellationToken cancellationToken)
    {
        using (_gate.EnterScope())
        {
            MintDue();
            RetireExpired();
        }

        return Task.CompletedTask;
    }

    /// <summary>
    /// Mints a key for any role whose newest one has served longer than the rotation period.
    /// </summary>
    private void MintDue()
    {
        var now = _timeProvider.GetUtcNow();

        foreach (var (usage, algorithm) in Roles())
        {
            var newest = (
                from minted in _keys
                where minted.Key.Usage == usage
                select (DateTimeOffset?)minted.CreatedAt).Max();

            if (newest is { } mintedAt && now - mintedAt < _policy.RotateEvery)
                continue;

            _keys.Add(new MintedKey(
                JsonWebKeyFactory.CreateRsa(usage, algorithm, _policy.RsaKeySize),
                now));
        }
    }

    /// <summary>
    /// Drops keys that have been retired long enough that nothing they produced can still be in use.
    /// </summary>
    private void RetireExpired()
    {
        var now = _timeProvider.GetUtcNow();

        foreach (var usage in _keys.Select(minted => minted.Key.Usage).Distinct().ToList())
        {
            // The newest key of a role is never dropped, however old it is: dropping it would leave the role
            // with nothing to produce with, which is worse than serving one past its rotation date.
            var newest = _keys.Where(minted => minted.Key.Usage == usage).Max(minted => minted.CreatedAt);

            _keys.RemoveAll(minted =>
                minted.Key.Usage == usage &&
                minted.CreatedAt != newest &&
                now - minted.CreatedAt > _policy.RotateEvery + _policy.KeepRetiredFor);
        }
    }

    /// <summary>The roles this ring mints for, and the algorithm each uses.</summary>
    private IEnumerable<(string Usage, string Algorithm)> Roles()
    {
        yield return (PublicKeyUsages.Signature, _policy.SigningAlgorithm);

        if (_policy.EncryptionAlgorithm is { } encryptionAlgorithm)
            yield return (PublicKeyUsages.Encryption, encryptionAlgorithm);
    }

    private sealed record MintedKey(JsonWebKey Key, DateTimeOffset CreatedAt);
}
