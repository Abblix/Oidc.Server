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
    /// Readies the ring of <paramref name="partition"/> to serve: builds it and refreshes it once, which mints its
    /// first key, so the first request for it finds a key to produce with. A ring already built is left as it is.
    /// </summary>
    /// <param name="partition">The partition to open, named of letters, digits, '-', '_' and '~' only.</param>
    /// <param name="cancellationToken">Cancels the refresh.</param>
    /// <exception cref="ArgumentException">The name cannot name a partition.</exception>
    /// <exception cref="InvalidOperationException">Existing keys are adopted, which only the unnamed partition
    /// takes.</exception>
    Task OpenAsync(string partition, CancellationToken cancellationToken);
}
