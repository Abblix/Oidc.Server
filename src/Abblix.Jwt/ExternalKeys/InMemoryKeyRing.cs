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
// An Adapter: presents the set of keys it rotates as a ring, on the host's settings
public sealed class InMemoryKeyRing : IKeyRing
{
    private readonly KeyRingOptions _options;
    private readonly InMemoryKeySet _keys;

    /// <summary>
    /// Creates the ring.
    /// </summary>
    public InMemoryKeyRing(LocalKeys policy, IOptions<KeyRingOptions> options, TimeProvider timeProvider)
    {
        _options = options.Value;
        _keys = new InMemoryKeySet(policy, timeProvider);
    }

    /// <inheritdoc />
    public IEnumerable<JsonWebKey> Get(string usage, bool includePrivateKeys)
        // Minting here rather than only in RefreshAsync so a ring that is asked before its first refresh answers
        // with a key instead of an empty set. A host without the refresh service running at all still gets a
        // working ring, it simply never rotates.
        => _keys.RotateAndServe(usage, includePrivateKeys, _options.KeyRolloverPropagation);

    /// <inheritdoc />
    /// <remarks>
    /// Nothing is minted or retired on the way: this answers what the ring holds, and a caller asking how stale
    /// the ring is must not be the thing that freshens it.
    /// </remarks>
    public DateTimeOffset? NewestKeyCreatedAt(string usage) => _keys.NewestCreatedAt(usage);

    /// <inheritdoc />
    public Task RefreshAsync(CancellationToken cancellationToken)
    {
        _keys.Rotate();
        return Task.CompletedTask;
    }
}
