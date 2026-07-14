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
using Abblix.Jwt.Encryption;
using Abblix.Jwt.Signing;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Jwt;

/// <summary>
/// Default <see cref="ICryptoRouter"/>: routes each private-key cryptographic operation to the in-process
/// keyed primitive when the key carries its secret material, to a host-provided external custodian
/// (<see cref="IExternalSigner"/> / <see cref="IExternalKeyEncryptor"/>) by <c>kid</c> when it does not,
/// and fails closed when a public-only key has no port or names an operation with no external form. The
/// in-process paths are byte-identical to the previous dispatch.
/// </summary>
/// <param name="serviceProvider">Resolves the keyed byte-primitives (signers, key encryptors) by algorithm.</param>
/// <param name="externalSigner">Optional host port that signs with an external key custodian
/// (HSM/KMS/vault). Absent (null) means no external signing keys. It is an optional dependency with a null
/// default, so the container passes null when the host registers no port.</param>
/// <param name="externalKeyEncryptor">Optional host port for JWE key management with an external key
/// custodian (RSA/symmetric unwrap, symmetric wrap, ECDH agreement). Absent (null) means no external
/// encryption keys.</param>
internal sealed class CryptoRouter(
    IServiceProvider serviceProvider,
    IExternalSigner? externalSigner = null,
    IExternalKeyEncryptor? externalKeyEncryptor = null) : ICryptoRouter
{
    /// <inheritdoc />
    public ValueTask<byte[]> SignAsync(
        JsonWebKey signingKey,
        string algorithm,
        byte[] data,
        CancellationToken cancellationToken)
    {
        // Secret material present: sign in process with the keyed primitive (the unchanged path).
        if (signingKey.HasPrivateKey)
            return new ValueTask<byte[]>(SignLocally(signingKey));

        // No private material means the key is published public-only, its private half held by an
        // external custodian. Route to the host port by kid; the absence of private material, not a flag,
        // is what selects the remote path. This is the single home of that decision (moved out of
        // JsonWebTokenSigner), so the same invariant will govern the shared protected-data seal.
        if (externalSigner != null)
        {
            // The kid published in the token and JWKS IS the custodian's handle - no separate identifier
            // and no mapping - so an external key must carry one.
            var kid = signingKey.KeyId ?? throw new InvalidOperationException(
                "An external signing key must carry a 'kid': it is the key custodian's handle.");

            return externalSigner.SignAsync(kid, algorithm, data, cancellationToken);
        }

        // Fail closed: a public-only key with no external signer cannot sign.
        throw new InvalidOperationException(
            $"Signing requires private key material for key (kid={signingKey.KeyId}); it carries none " +
            "and no external signer is configured.");

        byte[] SignLocally(JsonWebKey key) => key switch
        {
            RsaJsonWebKey rsaKey => SignBy(rsaKey),
            EllipticCurveJsonWebKey ecKey => SignBy(ecKey),
            OctetJsonWebKey octetKey => SignBy(octetKey),
            _ => throw new InvalidOperationException($"No signer registered for key type: {key.GetType().Name}"),
        };

        byte[] SignBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var dataSigner = serviceProvider.GetRequiredKeyedService<IDataSigner<TJsonWebKey>>(algorithm);
            return dataSigner.Sign(jwk, data);
        }
    }

    /// <inheritdoc />
    public async ValueTask<(byte[] contentEncryptionKey, byte[] encryptedKey)> EncryptKeyAsync(
        JsonWebTokenHeader header,
        JsonWebKey encryptionKey,
        string algorithm,
        int contentKeySizeInBytes,
        CancellationToken cancellationToken)
    {
        // Asymmetric key management (RSA, ECDH-ES) encrypts with the recipient's public half, so it runs
        // in process even for an external key - the public half is present. Only a symmetric key whose
        // secret bytes are absent must be wrapped by the external custodian.
        if (encryptionKey is OctetJsonWebKey { HasPrivateKey: false })
        {
            if (!IsExternallyWrappable(algorithm))
                throw NoExternalForm(encryptionKey, algorithm);

            var port = externalKeyEncryptor ?? throw NoKeyEncryptorPort(encryptionKey);
            var cek = CryptoRandom.GetRandomBytes(contentKeySizeInBytes);
            var wrapped = await port.WrapKeyAsync(RequireKid(encryptionKey), algorithm, header, cek, cancellationToken);
            return (cek, wrapped);
        }

        // In-process dispatch to the keyed primitive, unchanged from the previous encryptor logic.
        return EncryptLocally(encryptionKey);

        (byte[], byte[]) EncryptLocally(JsonWebKey key) => key switch
        {
            RsaJsonWebKey rsaKey => EncryptBy(rsaKey),
            OctetJsonWebKey octetKey => EncryptBy(octetKey),
            EllipticCurveJsonWebKey ecKey => EncryptBy(ecKey),
            _ => throw new InvalidOperationException($"No key encryptor registered for key type: {key.GetType().Name}"),
        };

        (byte[], byte[]) EncryptBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var keyEncryptor = serviceProvider.GetRequiredKeyedService<IKeyEncryptor<TJsonWebKey>>(algorithm);
            var cek = keyEncryptor.GenerateContentEncryptionKey(header, jwk, contentKeySizeInBytes);
            return (cek, keyEncryptor.EncryptKey(header, jwk, cek));
        }
    }

    /// <inheritdoc />
    public async ValueTask<byte[]?> DecryptKeyAsync(
        JsonWebTokenHeader header,
        JsonWebKey decryptionKey,
        string algorithm,
        byte[] encryptedKey,
        CancellationToken cancellationToken)
    {
        // Secret material present: unwrap in process with the keyed primitive (the unchanged path). The
        // "must have private material" gate that used to live in the encryptor is now this branch.
        if (decryptionKey.HasPrivateKey)
            return DecryptLocally(decryptionKey);

        // Public-only key: route the private operation to the external custodian by kid. Here 'algorithm'
        // and 'kid' come from the attacker-supplied JWE header, so anything this cannot handle returns null
        // and the caller substitutes a random CEK for a uniform failure (RFC 7516 §11.5). A throw would be
        // an oracle or a DoS; a genuinely missing port is a misconfiguration the startup guard rejects at
        // boot, not at request time.
        if (externalKeyEncryptor is not { } port || decryptionKey.KeyId is not { } kid)
            return null;

        return decryptionKey switch
        {
            // RSA decrypt and symmetric unwrap are single remote calls. The algorithm must match the key
            // type, mirroring the keyed-DI validation the in-process path gets for free.
            RsaJsonWebKey when IsExternalRsaAlgorithm(algorithm)
                => await port.UnwrapKeyAsync(kid, algorithm, header, encryptedKey, cancellationToken),
            OctetJsonWebKey when IsExternallyWrappable(algorithm)
                => await port.UnwrapKeyAsync(kid, algorithm, header, encryptedKey, cancellationToken),

            // ECDH-ES: only the agreement needs the private key, so only it is remote; the KDF and any AES
            // key unwrap run locally on the returned shared secret.
            EllipticCurveJsonWebKey ecKey when IsEcdhEsAlgorithm(algorithm) => await AgreeExternallyAsync(
                header, ecKey, algorithm, encryptedKey, port, kid, cancellationToken),

            // dir / PBES2, or an algorithm that does not match the key type: no external form, uniform null.
            _ => null,
        };

        byte[]? DecryptLocally(JsonWebKey key) => key switch
        {
            RsaJsonWebKey rsaKey => TryDecryptBy(rsaKey),
            OctetJsonWebKey octetKey => TryDecryptBy(octetKey),
            EllipticCurveJsonWebKey ecKey => TryDecryptBy(ecKey),
            _ => null,
        };

        byte[]? TryDecryptBy<TJsonWebKey>(TJsonWebKey jwk) where TJsonWebKey : JsonWebKey
        {
            var keyEncryptor = serviceProvider.GetKeyedService<IKeyEncryptor<TJsonWebKey>>(algorithm);
            return keyEncryptor != null && keyEncryptor.TryDecryptKey(header, jwk, encryptedKey, out var cek)
                ? cek
                : null;
        }
    }

    /// <summary>
    /// External ECDH-ES: the custodian performs the agreement with the recipient's private key and returns
    /// the raw shared secret Z; the Concat KDF and any AES key unwrap run locally. Mirrors the guards of
    /// the in-process EcdhEsKeyEncryptor.TryDecryptKey - only the agreement step is remote.
    /// </summary>
    private async ValueTask<byte[]?> AgreeExternallyAsync(
        JsonWebTokenHeader header,
        EllipticCurveJsonWebKey recipientKey,
        string algorithm,
        byte[] encryptedKey,
        IExternalKeyEncryptor port,
        string kid,
        CancellationToken cancellationToken)
    {
        // 'epk', 'apu' and 'apv' come from the attacker-supplied header, so a malformed value fails as a
        // uniform null (mirroring the in-process EcdhEsKeyEncryptor.TryDecryptKey) rather than throwing.
        try
        {
            // RFC 7518 §4.6.2: when both 'apu' and 'apv' are present they must differ, otherwise the
            // producer and recipient identities collapse and the KDF binding loses meaning.
            var apu = header.AgreementPartyUInfo;
            var apv = header.AgreementPartyVInfo;
            if (apu != null && apv != null && string.Equals(apu, apv, StringComparison.Ordinal))
                return null;

            // The originator's ephemeral public key is mandatory and must live on the recipient's curve.
            if (header.EphemeralPublicKey is not EllipticCurveJsonWebKey { HasPublicKey: true } ephemeralKey
                || !string.Equals(ephemeralKey.Curve, recipientKey.Curve, StringComparison.Ordinal))
                return null;

            // Z is the raw ECDH shared secret (NIST SP 800-56A / RFC 7518 §4.6); here it comes from the
            // custodian rather than an in-process agreement, but the KDF over it is identical.
            var sharedSecretZ = await port.AgreeKeyAsync(kid, algorithm, ephemeralKey, cancellationToken);
            try
            {
                if (KeyWrapSize(algorithm) is { } kekSize)
                {
                    var kek = ConcatKeyDerivation.DeriveKey(sharedSecretZ, algorithm, apu, apv, kekSize);
                    return AesKeyWrap.TryUnwrap(kek, encryptedKey, out var cek) ? cek : null;
                }

                // Direct Key Agreement: the encrypted key must be empty and the derived key IS the CEK,
                // sized for the content encryption algorithm named by 'enc'.
                if (encryptedKey.Length != 0)
                    return null;

                if (header.EncryptionAlgorithm is not { } contentEncryptionAlgorithm
                    || serviceProvider.GetKeyedService<IDataEncryptor>(contentEncryptionAlgorithm) is not { } contentEncryptor)
                    return null;

                return ConcatKeyDerivation.DeriveKey(
                    sharedSecretZ, contentEncryptionAlgorithm, apu, apv, contentEncryptor.KeySizeInBytes);
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

    /// <summary>
    /// The symmetric key-management algorithms whose wrap/unwrap an external custodian can perform. Direct
    /// encryption (dir) and PBES2 are excluded by construction: dir's CEK is the shared secret itself, and
    /// PBES2 derives the KEK from the secret by a password KDF, so neither has a remote wrap/unwrap form.
    /// </summary>
    private static bool IsExternallyWrappable(string algorithm) => algorithm switch
    {
        EncryptionAlgorithms.KeyManagement.Aes128KW or
        EncryptionAlgorithms.KeyManagement.Aes192KW or
        EncryptionAlgorithms.KeyManagement.Aes256KW or
        EncryptionAlgorithms.KeyManagement.Aes128Gcmkw or
        EncryptionAlgorithms.KeyManagement.Aes192Gcmkw or
        EncryptionAlgorithms.KeyManagement.Aes256Gcmkw => true,
        _ => false,
    };

    /// <summary>The RSA key-transport algorithms an external RSA key can decrypt.</summary>
    private static bool IsExternalRsaAlgorithm(string algorithm) => algorithm switch
    {
        EncryptionAlgorithms.KeyManagement.RsaOaep or
        EncryptionAlgorithms.KeyManagement.RsaOaep256 or
        EncryptionAlgorithms.KeyManagement.Rsa1_5 => true,
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
    /// The RFC 3394 KEK size for the ECDH-ES key-wrapping variants, or null for Direct Key Agreement where
    /// the derived key is the CEK itself. Mirrors EcdhEsKeyEncryptor's mode selection for the remote path.
    /// </summary>
    private static int? KeyWrapSize(string algorithm) => algorithm switch
    {
        EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW => 16,
        EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW => 24,
        EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW => 32,
        _ => null,
    };

    private static string RequireKid(JsonWebKey key)
        => key.KeyId ?? throw new InvalidOperationException(
            "An external key must carry a 'kid': it is the key custodian's handle.");

    private static InvalidOperationException NoKeyEncryptorPort(JsonWebKey key)
        => new($"Key (kid={key.KeyId}) has no secret material and no {nameof(IExternalKeyEncryptor)} is " +
               "configured to serve it from an external custodian.");

    private static InvalidOperationException NoExternalForm(JsonWebKey key, string algorithm)
        => new($"Key (kid={key.KeyId}) is external, but the key-management algorithm '{algorithm}' has no " +
               "external form (direct and password-based key management cannot be externalised); failing closed.");
}
