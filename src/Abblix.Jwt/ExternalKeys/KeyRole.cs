// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>A role a ring mints a key for: what the key is used for, and under which algorithm.</summary>
/// <param name="Usage">The key's use, signing or encryption.</param>
/// <param name="Algorithm">The algorithm the key serves.</param>
internal readonly record struct KeyRole(string Usage, string Algorithm)
{
    /// <summary>The roles a policy mints for: always signing, and encryption only when asked for.</summary>
    public static IEnumerable<KeyRole> Of(MintedKeys policy)
    {
        yield return new KeyRole(PublicKeyUsages.Signature, policy.SigningAlgorithm);

        if (policy.EncryptionAlgorithm is { } encryption)
            yield return new KeyRole(PublicKeyUsages.Encryption, encryption);
    }
}
