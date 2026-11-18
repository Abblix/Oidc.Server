// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Encryption;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// The external-custodian decryption backend (<see cref="IContentKeyDecryptor"/>): owns public-only keys and recovers
/// the Content Encryption Key through an <see cref="IKeyCustodian"/> (an HSM/KMS/vault), addressing it by the
/// key's <c>kid</c>. RSA decryption and symmetric unwrap are single remote calls; ECDH-ES sends only the
/// agreement to the custodian (<see cref="ExternalEcdhEsRecipient"/>). Anything the custodian cannot serve (an
/// algorithm with no external form, or one that does not match the key type) returns null, so the RFC 7516
/// section 11.5 mitigation upstream sees a uniform failure.
/// </summary>
internal sealed class ExternalKeyDecryptor(IKeyCustodian custodian, IServiceProvider serviceProvider)
    : IContentKeyDecryptor
{
    private readonly ExternalEcdhEsRecipient _ecdhEs = new(custodian, new EcdhEsContentKey(serviceProvider));

    /// <summary>Owns any public-only key: its private half lives with the custodian, not in process.</summary>
    public bool CanDecrypt(JsonWebKey key) => !key.HasPrivateKey;

    public async Task<byte[]?> DecryptKeyAsync(
        JsonWebTokenHeader header,
        JsonWebKey key,
        string algorithm,
        byte[] encryptedKey,
        CancellationToken cancellationToken)
    {
        // 'algorithm' and 'kid' come from the attacker-supplied JWE header, so anything this cannot handle
        // returns null and the caller substitutes a random CEK for a uniform failure (RFC 7516 section 11.5). The kid
        // published in the token IS the custodian's handle, so an external key must carry one.
        if (key.KeyId is not { } keyId)
            return null;

        return key switch
        {
            // RSA decrypt and symmetric unwrap are single remote calls. The algorithm must match the key type,
            // mirroring the keyed-DI validation the in-process path gets for free.
            RsaJsonWebKey when ExternalKeyAlgorithms.Rsa.Contains(algorithm)
                => await custodian.UnwrapKeyAsync(keyId, algorithm, header, encryptedKey, cancellationToken),

            OctetJsonWebKey when ExternalKeyAlgorithms.Unwrappable.Contains(algorithm)
                => await custodian.UnwrapKeyAsync(keyId, algorithm, header, encryptedKey, cancellationToken),

            // ECDH-ES: only the agreement needs the private key, so only it is remote.
            EllipticCurveJsonWebKey ecKey when ExternalKeyAlgorithms.EcdhEs.Contains(algorithm)
                => await _ecdhEs.TryDecryptKeyAsync(header, ecKey, algorithm, encryptedKey, keyId, cancellationToken),

            // dir / PBES2, or an algorithm that does not match the key type: no external form, uniform null.
            _ => null,
        };
    }
}
