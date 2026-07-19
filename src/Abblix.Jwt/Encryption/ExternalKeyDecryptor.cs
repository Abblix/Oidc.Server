// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Security.Cryptography;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt.Encryption;

/// <summary>
/// The external-custodian decryption backend (<see cref="IContentKeyDecryptor"/>): owns public-only keys and recovers
/// the Content Encryption Key through an <see cref="IKeyCustodian"/> (an HSM/KMS/vault), addressing it by the
/// key's <c>kid</c>. RSA decryption and symmetric unwrap are single remote calls; ECDH-ES sends only the
/// agreement to the custodian and runs the Concat KDF and any AES key unwrap in process on the returned shared
/// secret. Anything the custodian cannot serve (an algorithm with no external form, or one that does not match
/// the key type) returns null, so the RFC 7516 §11.5 mitigation upstream sees a uniform failure.
/// </summary>
internal sealed class ExternalKeyDecryptor(IKeyCustodian custodian, IServiceProvider serviceProvider)
    : IContentKeyDecryptor
{
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
        // returns null and the caller substitutes a random CEK for a uniform failure (RFC 7516 §11.5). The kid
        // published in the token IS the custodian's handle, so an external key must carry one.
        if (key.KeyId is not { } keyId)
            return null;

        return key switch
        {
            // RSA decrypt and symmetric unwrap are single remote calls. The algorithm must match the key type,
            // mirroring the keyed-DI validation the in-process path gets for free.
            RsaJsonWebKey when IsExternalRsaAlgorithm(algorithm)
                => await custodian.UnwrapKeyAsync(keyId, algorithm, header, encryptedKey, cancellationToken),

            OctetJsonWebKey when IsExternallyUnwrappable(algorithm)
                => await custodian.UnwrapKeyAsync(keyId, algorithm, header, encryptedKey, cancellationToken),

            // ECDH-ES: only the agreement needs the private key, so only it is remote; the KDF and any AES key
            // unwrap run locally on the returned shared secret.
            EllipticCurveJsonWebKey ecKey when IsEcdhEsAlgorithm(algorithm)
                => await AgreeExternallyAsync(header, ecKey, algorithm, encryptedKey, keyId, cancellationToken),

            // dir / PBES2, or an algorithm that does not match the key type: no external form, uniform null.
            _ => null,
        };
    }

    /// <summary>
    /// External ECDH-ES: the custodian performs the agreement with the recipient's private key and returns the
    /// raw shared secret Z; the Concat KDF and any AES key unwrap run locally. Mirrors the guards of the
    /// in-process EcdhEsKeyEncryptor.TryDecryptKey - only the agreement step is remote.
    /// </summary>
    private async Task<byte[]?> AgreeExternallyAsync(
        JsonWebTokenHeader header,
        EllipticCurveJsonWebKey recipientKey,
        string algorithm,
        byte[] encryptedKey,
        string keyId,
        CancellationToken cancellationToken)
    {
        // 'epk', 'apu' and 'apv' come from the attacker-supplied header, so a malformed value fails as a uniform
        // null (mirroring the in-process EcdhEsKeyEncryptor.TryDecryptKey) rather than throwing.
        try
        {
            // RFC 7518 §4.6.2: when both 'apu' and 'apv' are present they must differ, otherwise the producer
            // and recipient identities collapse and the KDF binding loses meaning.
            var apu = header.AgreementPartyUInfo;
            var apv = header.AgreementPartyVInfo;
            if (apu != null && apv != null && string.Equals(apu, apv, StringComparison.Ordinal))
                return null;

            // The originator's ephemeral public key is mandatory and must live on the recipient's curve.
            if (header.EphemeralPublicKey is not EllipticCurveJsonWebKey { HasPublicKey: true } ephemeralKey)
                return null;

            if (!string.Equals(ephemeralKey.Curve, recipientKey.Curve, StringComparison.Ordinal))
                return null;

            // Z is the raw ECDH shared secret (NIST SP 800-56A / RFC 7518 §4.6); here it comes from the
            // custodian rather than an in-process agreement, but the KDF over it is identical.
            var sharedSecretZ = await custodian.AgreeKeyAsync(keyId, algorithm, ephemeralKey, cancellationToken);
            try
            {
                if (KeyWrapSize(algorithm) is { } keyEncryptionKeySize)
                {
                    var keyEncryptionKey = ConcatKeyDerivation.DeriveKey(sharedSecretZ, algorithm, apu, apv, keyEncryptionKeySize);
                    return AesKeyWrap.TryUnwrap(keyEncryptionKey, encryptedKey, out var contentEncryptionKey) ? contentEncryptionKey : null;
                }

                // Direct Key Agreement: the encrypted key must be empty and the derived key IS the CEK, sized
                // for the content encryption algorithm named by 'enc'.
                if (encryptedKey.Length != 0)
                    return null;

                if (header.EncryptionAlgorithm is not { } contentEncryptionAlgorithm)
                    return null;

                var encryptor = serviceProvider.GetKeyedService<IContentEncryptionAlgorithm>(contentEncryptionAlgorithm);
                if (encryptor == null)
                    return null;

                return ConcatKeyDerivation.DeriveKey(
                    sharedSecretZ,
                    contentEncryptionAlgorithm,
                    apu,
                    apv,
                    encryptor.KeySizeInBytes);
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

    /// <summary>The RSA key-transport algorithms an external RSA key can decrypt.</summary>
    private static bool IsExternalRsaAlgorithm(string algorithm) => algorithm switch
    {
        EncryptionAlgorithms.KeyManagement.RsaOaep or
        EncryptionAlgorithms.KeyManagement.RsaOaep256 or
        EncryptionAlgorithms.KeyManagement.Rsa1_5 => true,
        _ => false,
    };

    /// <summary>
    /// The symmetric key-management algorithms whose unwrap an external custodian can perform. Direct encryption
    /// (dir) and PBES2 are excluded by construction: dir's CEK is the shared secret itself, and PBES2 derives the
    /// KEK from the secret by a password KDF, so neither has a remote unwrap form.
    /// </summary>
    private static bool IsExternallyUnwrappable(string algorithm) => algorithm switch
    {
        EncryptionAlgorithms.KeyManagement.Aes128KW or
        EncryptionAlgorithms.KeyManagement.Aes192KW or
        EncryptionAlgorithms.KeyManagement.Aes256KW or
        EncryptionAlgorithms.KeyManagement.Aes128Gcmkw or
        EncryptionAlgorithms.KeyManagement.Aes192Gcmkw or
        EncryptionAlgorithms.KeyManagement.Aes256Gcmkw => true,
        _ => false,
    };

    /// <summary>The ECDH-ES family an external EC key can agree.</summary>
    private static bool IsEcdhEsAlgorithm(string algorithm) => algorithm switch
    {
        EncryptionAlgorithms.KeyManagement.EcdhEs or
        EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW or
        EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW or
        EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW => true,
        _ => false,
    };

    /// <summary>
    /// The RFC 3394 KEK size for the ECDH-ES key-wrapping variants, or null for Direct Key Agreement where the
    /// derived key is the CEK itself. Mirrors EcdhEsKeyEncryptor's mode selection for the remote path.
    /// </summary>
    private static int? KeyWrapSize(string algorithm) => algorithm switch
    {
        EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW => 128 >> 3,
        EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW => 192 >> 3,
        EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW => 256 >> 3,
        _ => null,
    };
}
