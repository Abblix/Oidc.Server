// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Azure;

partial class KeyVaultClient
{
    // Static with an explicit logger parameter, unlike the instance log methods elsewhere: this type has two
    // constructors and so holds the logger in a field rather than a primary-constructor parameter, and passing
    // that field here is the one place the field is read in source, which an instance method would leave only to
    // generated code.
    [LoggerMessage(
        EventId = LogEvents.KeyVaultClient.UnwrapRejected,
        Level = LogLevel.Warning,
        Message = "Key Vault rejected an unwrap for key '{KeyId}': the ciphertext is a wrong or tampered key, or " +
                  "the version that wrapped it is disabled. No key material is logged.")]
    private static partial void LogUnwrapRejected(ILogger logger, string keyId);

    [LoggerMessage(
        EventId = LogEvents.KeyVaultClient.AlgorithmNotServed,
        Level = LogLevel.Warning,
        Message = "Key Vault does not serve '{Algorithm}' for key '{KeyId}', so the token was refused without " +
                  "asking the vault. Key Vault decrypts under the RSA algorithms and agrees no ECDH-ES; " +
                  "a key published with an algorithm the store cannot serve makes every token sent to it fail " +
                  "this way, so check the key's configured algorithm if this repeats.")]
    private static partial void LogAlgorithmNotServed(ILogger logger, Sanitized Algorithm, string KeyId);
}
