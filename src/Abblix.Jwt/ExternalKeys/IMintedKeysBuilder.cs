// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The continuation of <c>UseKeysInProcess</c>: the placement that mints its own keys must say where the ring lives,
/// and the packages hang their <c>PersistRingTo...</c> calls off this.
/// </summary>
/// <remarks>
/// A ring store belongs to this placement and to no other, so it attaches here rather than to the service collection:
/// there is nothing to register a store onto unless the placement that needs one was chosen. The placement where the
/// custodian holds every key has no ring at all.
/// </remarks>
public interface IMintedKeysBuilder
{
    /// <summary>The collection a <c>PersistRingTo...</c> call registers the store into.</summary>
    IServiceCollection Services { get; }

    /// <summary>
    /// Takes keys the server already signs with into the ring, so that switching to minted keys does not change
    /// which key produces on the day it happens.
    /// </summary>
    /// <param name="keys">The keys to take, private halves included - the ring seals what it is given, and a key
    /// without its private half can be published but cannot sign.</param>
    /// <returns>The same builder, so the <c>PersistRingTo...</c> call follows.</returns>
    /// <remarks>
    /// This is a migration call and is meant to be deleted once the ring has rotated past the keys it names, but
    /// nothing breaks if it is not: keys are taken only into an EMPTY ring, so from the first entry onward the
    /// call does nothing. See <see cref="MintedKeys.AdoptedKeys"/> for what adoption does to the ordering.
    /// </remarks>
    IMintedKeysBuilder AdoptExistingKeys(params JsonWebKey[] keys);
}
