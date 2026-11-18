// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Frozen;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The key management algorithms a key held by an external custodian can serve, by the kind of key.
/// </summary>
/// <remarks>
/// The algorithm comes from the token header, so it has to match the key type before anything is sent to the
/// custodian, as keyed registration does for the in-process path. Direct encryption (dir) and PBES2 have no external
/// form: dir's Content Encryption Key is the shared secret itself, and PBES2 derives the key encryption key from it
/// by a password KDF.
/// </remarks>
internal static class ExternalKeyAlgorithms
{
    /// <summary>The RSA key-transport algorithms an external RSA key can decrypt.</summary>
    public static readonly FrozenSet<string> Rsa = FrozenSet.Create(
        StringComparer.Ordinal,
        EncryptionAlgorithms.KeyManagement.RsaOaep,
        EncryptionAlgorithms.KeyManagement.RsaOaep256,
        EncryptionAlgorithms.KeyManagement.Rsa1_5);

    /// <summary>The symmetric key-management algorithms whose unwrap an external custodian can perform.</summary>
    public static readonly FrozenSet<string> Unwrappable = FrozenSet.Create(
        StringComparer.Ordinal,
        EncryptionAlgorithms.KeyManagement.Aes128KW,
        EncryptionAlgorithms.KeyManagement.Aes192KW,
        EncryptionAlgorithms.KeyManagement.Aes256KW,
        EncryptionAlgorithms.KeyManagement.Aes128Gcmkw,
        EncryptionAlgorithms.KeyManagement.Aes192Gcmkw,
        EncryptionAlgorithms.KeyManagement.Aes256Gcmkw);

    /// <summary>The ECDH-ES family an external elliptic curve key can agree.</summary>
    public static readonly FrozenSet<string> EcdhEs = FrozenSet.Create(
        StringComparer.Ordinal,
        EncryptionAlgorithms.KeyManagement.EcdhEs,
        EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW,
        EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW,
        EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW);
}
