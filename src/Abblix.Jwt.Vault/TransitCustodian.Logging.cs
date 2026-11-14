// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Vault;

partial class TransitCustodian
{
    [LoggerMessage(
        EventId = LogEvents.TransitCustodian.UnwrapRejected,
        Level = LogLevel.Warning,
        Message = "Vault Transit rejected an unwrap for key '{KeyId}': the ciphertext is a wrong or tampered key, " +
                  "or the version that wrapped it has been retired. No key material is logged.")]
    private partial void LogUnwrapRejected(string keyId);

    [LoggerMessage(
        EventId = LogEvents.TransitCustodian.AlgorithmNotServed,
        Level = LogLevel.Warning,
        Message = "Vault Transit does not serve '{Algorithm}' for key '{KeyId}', so the encrypted message was refused without " +
                  "asking Vault. Transit decrypts under RSA-OAEP-256 and agrees no ECDH-ES; " +
                  "a key configured with an algorithm the store cannot serve makes every message encrypted to it " +
                  "fail this way, so check the key's configured algorithm if this repeats.")]
    private partial void LogAlgorithmNotServed(Sanitized Algorithm, string KeyId);

    [LoggerMessage(
        EventId = LogEvents.TransitCustodian.CustodianFailed,
        Level = LogLevel.Error,
        Message = "Vault Transit could not answer for '{Path}'. Temporary: {Temporary}, which is what decides " +
                  "whether a caller is told to come back. What the caller actually receives is decided upstream: " +
                  "a published key set already read can be served instead of the failure.")]
    private partial void LogCustodianFailed(string path, bool temporary, Exception exception);
}
