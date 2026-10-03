// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The rings of every partition the key ring keeps (<see cref="IKeyRingPartitions"/>), one for each issuer a
/// server serves, so each issuer mints, rotates and serves keys of its own.
/// </summary>
public interface IKeyRings
{
    /// <summary>
    /// The ring of <paramref name="partition"/>.
    /// </summary>
    /// <param name="partition">A partition the ring keeps, or one opened by <see cref="OpenAsync"/>.</param>
    /// <exception cref="InvalidOperationException">The ring keeps no such partition.</exception>
    IKeyRing For(string partition);

    /// <summary>
    /// Readies the rings of <paramref name="partitions"/> to serve, each on its own: builds each not built yet and
    /// refreshes each not kept now, which mints a first key where none is due, so the first request for it finds a
    /// key to produce with. One read of the store serves them all.
    /// </summary>
    /// <param name="partitions">The partitions to open, each named of letters, digits, '-', '_' and '~' only.
    /// </param>
    /// <param name="cancellationToken">Cancels the opening of those not opened yet.</param>
    /// <returns>Why each partition that could not be opened was not, by its name: a name that cannot name a
    /// partition, keys adopted into the ring, which only the unnamed partition takes, or the store or the custodian
    /// failing. The others are ready.</returns>
    Task<IReadOnlyDictionary<string, Exception>> OpenAsync(
        IReadOnlyCollection<string> partitions,
        CancellationToken cancellationToken);

    /// <summary>
    /// Lets the ring of <paramref name="partition"/> go, its keys with it, once the issuer it served is gone for
    /// good; a ring not built is left alone. The partition's entries stay in the store.
    /// </summary>
    /// <param name="partition">The partition to close.</param>
    void Close(string partition);
}
