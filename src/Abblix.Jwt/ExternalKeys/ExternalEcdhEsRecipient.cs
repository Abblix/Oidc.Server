// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Security.Cryptography;
using System.Text.Json;
using Abblix.Jwt.Encryption;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The decrypting side of ECDH-ES (RFC 7518 section 4.6) with the private key held by an external custodian: the
/// custodian performs the agreement and returns the shared secret Z, and the rest runs in process.
/// </summary>
/// <remarks>
/// The checks on the header, the Concat KDF and any AES key unwrap are the in-process recipient's, shared through
/// <see cref="EcdhEsContentKey"/>; only the agreement step is remote.
/// </remarks>
/// <param name="custodian">Performs the agreement with the private key it holds.</param>
/// <param name="contentKey">Turns the shared secret into the Content Encryption Key.</param>
internal sealed class ExternalEcdhEsRecipient(IKeyCustodian custodian, EcdhEsContentKey contentKey)
{
    /// <summary>
    /// The Content Encryption Key, or null when the token does not open with the custodian's key
    /// <paramref name="keyId"/>.
    /// </summary>
    public async Task<byte[]?> TryDecryptKeyAsync(
        JsonWebTokenHeader header,
        EllipticCurveJsonWebKey recipientKey,
        string algorithm,
        byte[] encryptedKey,
        string keyId,
        CancellationToken cancellationToken)
    {
        // 'epk', 'apu' and 'apv' come from the attacker-supplied header, so a malformed value fails as a uniform
        // null, as it does in process, rather than throwing.
        try
        {
            if (EcdhEsContentKey.EphemeralKeyFor(header, recipientKey) is not { } ephemeralKey
                || contentKey.DerivationFor(header, algorithm, encryptedKey) is not { } derivation)
                return null;

            var sharedSecretZ = await custodian.AgreeKeyAsync(keyId, algorithm, ephemeralKey, cancellationToken);
            try
            {
                return EcdhEsContentKey.From(sharedSecretZ, header, derivation, encryptedKey);
            }
            finally
            {
                CryptographicOperations.ZeroMemory(sharedSecretZ);
            }
        }
        catch (JsonException)
        {
            return null; // malformed 'epk'
        }
        catch (FormatException)
        {
            return null; // malformed base64url in 'apu' / 'apv'
        }
        catch (CryptographicException)
        {
            return null; // agreement or key-unwrap failure
        }
    }
}
