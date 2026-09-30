// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The rings of every partition the key ring keeps (<see cref="KeyRingOptions.Partitions"/>), one for each issuer a
/// server serves, so each issuer mints, rotates and serves keys of its own.
/// </summary>
public interface IKeyRings
{
    /// <summary>
    /// The ring of <paramref name="partition"/>.
    /// </summary>
    /// <param name="partition">One of <see cref="KeyRingOptions.Partitions"/>.</param>
    /// <exception cref="InvalidOperationException">The ring keeps no such partition.</exception>
    IKeyRing For(string partition);
}
