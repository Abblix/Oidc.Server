// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The single-issuer form of <see cref="IMintedKeysBuilder.AdoptExistingKeys"/>.
/// </summary>
public static class MintedKeysBuilderExtensions
{
    /// <summary>
    /// Takes keys the server already signs with into the ring, so that switching to minted keys does not change
    /// which key produces on the day it happens.
    /// </summary>
    /// <param name="builder">The builder the placement returned.</param>
    /// <param name="keys">The keys to take, private halves included - the ring seals what it is given, and a key
    /// without its private half can be published but cannot sign.</param>
    /// <returns>The same builder, so the <c>PersistRingTo...</c> call follows.</returns>
    /// <remarks>
    /// The keys go into the ring's default partition (<see cref="KeyRingOptions.DefaultPartition"/>). This is a
    /// migration call and is meant to be deleted once the ring has rotated past the keys it names, but nothing breaks
    /// if it is not: keys are taken only until the ring holds its first minted key, so from then on the call does
    /// nothing. It goes with its partition, though: when every partition is known at startup, keys adopted into one
    /// the ring no longer keeps refuse the start and any opening of a partition. See
    /// <see cref="MintedKeys.AdoptedKeys"/> for what adoption does to the ordering.
    /// </remarks>
    public static IMintedKeysBuilder AdoptExistingKeys(this IMintedKeysBuilder builder, params JsonWebKey[] keys)
        => builder.AdoptExistingKeys(KeyRingOptions.DefaultPartition, keys);
}
