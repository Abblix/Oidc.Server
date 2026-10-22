// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
/// <para>
/// The steps of a refresh are <see cref="KeyRingRefresh"/>, shared by every ring of a policy, and the opened keys
/// are held by <see cref="HeldKeys"/>, one set per ring.
/// </para>
/// </remarks>
/// <param name="store">The ring's partition of the store.</param>
/// <param name="refresh">The steps of a refresh.</param>
/// <param name="schedule">The clock and the propagation window that decide which held key produces.</param>
/// <param name="partition">The name of the ring's partition, which the keys a host hands over are addressed to.</param>
/// <param name="check">Judges where the host adopted its keys before a refresh mints.</param>
internal sealed class KeyRing(
    IKeyRingStore store,
    KeyRingRefresh refresh,
    KeyRingSchedule schedule,
    string partition,
    KeyRingStartupCheck check) : IKeyRing
{
    private readonly HeldKeys _held = new(schedule);

    /// <inheritdoc cref="HeldKeys.Get" />
    public IEnumerable<JsonWebKey> Get(string usage, bool includePrivateKeys) => _held.Get(usage, includePrivateKeys);

    /// <inheritdoc />
    public DateTimeOffset? NewestKeyCreatedAt(string usage) => _held.NewestKeyCreatedAt(usage);

    /// <summary>
    /// Mints whatever the current period is missing, then reloads and opens the ring into memory.
    /// </summary>
    /// <param name="cancellationToken">Cancels the refresh.</param>
    /// <exception cref="InvalidOperationException">Keys are adopted where no partition takes them.</exception>
    public Task RefreshAsync(CancellationToken cancellationToken)
    {
        // The one path host code reaches before the start, which is judged before any partition opens: a partition
        // takes adopted keys only until it holds a key it minted, so a ring refreshed here first would mint, and a
        // corrected adoption would never be taken. The refresh rounds and openings come after that judgement.
        check.CheckAdoption();
        return RefreshAsync(store, cancellationToken);
    }

    /// <summary>
    /// Refreshes the ring from <paramref name="source"/>: a view of the store read once for every partition
    /// refreshed or opened in one round.
    /// </summary>
    /// <param name="source">Where the entries are read from and written to.</param>
    /// <param name="cancellationToken">Cancels the refresh.</param>
    internal async Task RefreshAsync(IKeyRingStore source, CancellationToken cancellationToken)
        => _held.Replace(await refresh.RunAsync(source, partition, cancellationToken));
}
