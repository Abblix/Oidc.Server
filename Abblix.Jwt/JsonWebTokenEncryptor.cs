using System.Diagnostics.CodeAnalysis;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;

using System.Buffers.Text;

namespace Abblix.Jwt;

/// <summary>
/// Handles encryption and decryption of JSON Web Encryption (JWE) tokens.
/// Implements RFC 7516 (JWE) encryption and decryption.
/// </summary>
/// <param name="serviceProvider">The service provider for resolving the keyed content encryptors and key
/// encryptors by algorithm.</param>
/// <param name="externalKeyEncryptor">Optional host port for JWE key management with an external key
/// custodian (RSA/symmetric unwrap, symmetric wrap, ECDH agreement) when a key is published public-only.
/// Absent (null) means no external encryption keys.</param>
internal class JsonWebTokenEncryptor(
    IServiceProvider serviceProvider,
    IExternalKeyEncryptor? externalKeyEncryptor = null) : IJsonWebTokenEncryptor
{
    /// <summary>
    /// Encrypts an inner JWS token to create a JWE token.
    /// Implements RFC 7516 (JWE) encryption.
    /// </summary>
    public async Task<string> EncryptAsync(
        byte[] plaintext,
        JsonWebKey encryptionKey,
        string? tokenType,
        string keyEncryptionAlgorithm,
        string contentEncryptionAlgorithm,
        CancellationToken cancellationToken = default)
    {
        // Key validation and the local-vs-external fail-closed decision live in EncryptKeyAsync below. The
        // public-key guard that used to sit here would reject an external symmetric key (which has no public
        // half), so it lives with the key-management routing, which knows what each key can actually do.

        // Resolve content encryptor to get required CEK size
        var contentEncryptor = serviceProvider.GetRequiredKeyedService<IContentEncryptionAlgorithm>(contentEncryptionAlgorithm);

        var header = new JsonWebTokenHeader(new JsonObject())
        {
            Algorithm = keyEncryptionAlgorithm,
            EncryptionAlgorithm = contentEncryptionAlgorithm,
            Type = tokenType,
            KeyId = encryptionKey.KeyId
        };

        // Produce the CEK and protect it, in process or via an external custodian. Key-wrapping algorithms
        // return a random CEK; "dir" returns the shared key itself; ECDH-ES derives the CEK from the
        // ephemeral-static agreement. Either step may add algorithm parameters to the header ('epk' for
        // ECDH-ES, 'iv'/'tag' for AES-GCM key wrap, 'p2s'/'p2c' for PBES2).
        var (cek, encryptedKey) = await EncryptKeyAsync(
            header,
            encryptionKey,
            keyEncryptionAlgorithm,
            contentEncryptor.KeySizeInBytes,
            cancellationToken);

        // Encode header AFTER key encryption (in case it was modified)
        var headerEncoded = EncodeJson(header.Json);

        // AAD is the encoded JWE header
        var additionalAuthenticatedData = Encoding.ASCII.GetBytes(headerEncoded);

        var (iv, ciphertext, authTag) = contentEncryptor.Encrypt(
            cek,
            plaintext,
            additionalAuthenticatedData);

        // JWE Compact Serialization: header.encryptedKey.iv.ciphertext.authTag
        return EncodeJwe(headerEncoded, encryptedKey, iv, ciphertext, authTag);
    }

    /// <summary>
    /// Encodes a JSON object to base64url string for JWT usage.
    /// </summary>
    private static string EncodeJson(JsonObject json)
    {
        var options = new JsonSerializerOptions { WriteIndented = false };
        var bytes = Encoding.UTF8.GetBytes(json.ToJsonString(options));
        return Base64Url.EncodeToString(bytes);
    }

    /// <summary>
    /// Encodes JWE parts into compact serialization format.
    /// </summary>
    private static string EncodeJwe(string header, params byte[][] parts)
    {
        return string.Join(".", parts
            .Select(p => Base64Url.EncodeToString(p))
            .Prepend(header));
    }

    /// <summary>
    /// Validates and decrypts JWE tokens using decoded byte parts and original string parts.
    /// Implements RFC 7516 (JWE) decryption.
    /// </summary>
    [SuppressMessage("Major Code Smell", "S3776:Cognitive Complexity of methods should not be too high",
        Justification = "The complexity is the linear sequence of RFC 7516 §5.2 mandated validation guards " +
                        "(base64, header JSON, enc/alg presence, decryptor resolution, per-key decryption); " +
                        "splitting the single decrypt flow would fragment it without improving readability. " +
                        "Covered by the JwtEncryptionTests decryption suite.")]
    public async Task<Result<byte[], JwtValidationError>> DecryptAsync(
        string[] jwtParts,
        IAsyncEnumerable<JsonWebKey> decryptionKeys,
        CancellationToken cancellationToken = default)
    {
        // Decode all JWE parts - invalid base64 means invalid token
        byte[][] decodedParts;
        try
        {
            decodedParts = Array.ConvertAll(jwtParts, static s => Base64Url.DecodeFromChars(s));
        }
        catch (FormatException)
        {
            return new JwtValidationError(JwtError.InvalidToken, "Invalid base64url encoding in JWE");
        }

        // Decode header JSON to get algorithms and key ID. A base64url-valid but non-JSON header (e.g. a
        // truncated object) makes JsonNode.Parse throw JsonException; catch it and map to a typed validation
        // error so an attacker-crafted JWE fails as invalid_token rather than surfacing as an unhandled 500.
        var headerJson = Encoding.UTF8.GetString(decodedParts[0]);
        JsonNode? headerNode;
        try
        {
            headerNode = JsonNode.Parse(headerJson);
        }
        catch (JsonException)
        {
            return new JwtValidationError(JwtError.InvalidToken, "Invalid JWE header: not valid JSON");
        }

        if (headerNode is not JsonObject headerObject)
            return new JwtValidationError(JwtError.InvalidToken, "Invalid JWE header: must be a JSON object");

        var header = new JsonWebTokenHeader(headerObject);

        var encryptionAlgorithm = header.EncryptionAlgorithm;
        if (encryptionAlgorithm == null)
            return new JwtValidationError(JwtError.InvalidToken, "Missing 'enc' algorithm in JWE header");

        var algorithm = header.Algorithm;
        if (algorithm == null)
            return new JwtValidationError(JwtError.InvalidToken, "Missing 'alg' algorithm in JWE header");

        // Per RFC 7517 Section 4.4, 'alg' parameter in JWK is OPTIONAL
        // Filter only by kid when present - algorithm compatibility is validated during decryption attempt
        if (header.KeyId.HasValue())
            decryptionKeys = decryptionKeys.Where(key => string.Equals(key.KeyId, header.KeyId, StringComparison.Ordinal));

        // Resolve the content decryptor by 'enc'. The registered set is the allow-list of content
        // encryption algorithms for incoming JWE — an unregistered 'enc' yields no decryptor and is
        // rejected outright.
        var contentDecryptor = serviceProvider.GetKeyedService<IContentEncryptionAlgorithm>(encryptionAlgorithm);
        if (contentDecryptor == null)
            return new JwtValidationError(JwtError.InvalidToken, "Unsupported 'enc' content encryption algorithm in JWE");

        var encryptedKey = decodedParts[1];
        var iv = decodedParts[2];
        var ciphertext = decodedParts[3];
        var authTag = decodedParts[4];
        var aad = Encoding.ASCII.GetBytes(jwtParts[0]);

        var keyFound = false;
        await foreach (var key in decryptionKeys.WithCancellation(cancellationToken))
        {
            keyFound = true;

            // DecryptKeyAsync recovers the CEK - in process for a local key, or via the external custodian
            // for a public-only key - and returns null on any decryption failure, which the mitigation below
            // turns into a uniform outcome. The "must have private material" gate lives with that routing.

            // RFC 7516 §11.5: substitute a randomly generated CEK of the correct size and still run the
            // AEAD step when CEK decryption fails — wrong key, malformed padding, or an unregistered
            // key-management 'alg' — OR when it succeeds with a structurally valid but wrong-length key.
            // The authentication tag then fails exactly as it would for a successful-but-wrong CEK, so a
            // decryption failure is processed identically regardless of its cause. The wrong-length case
            // matters because a content decryptor fast-fails on a length mismatch before doing the
            // AEAD/HMAC work, whereas a correct-length random CEK runs the full step — leaving that
            // difference in place would be an observable timing oracle signalling valid PKCS1 padding.
            // This is what makes RSA1_5 (RSAES-PKCS1-v1_5) safe to support: it closes the
            // Bleichenbacher/Manger padding oracle by removing the observable difference between valid
            // and invalid padding.
            var contentEncryptionKey = await DecryptKeyAsync(header, key, algorithm, encryptedKey, cancellationToken);
            if (contentEncryptionKey == null || contentEncryptionKey.Length != contentDecryptor.KeySizeInBytes)
                contentEncryptionKey = CryptoRandom.GetRandomBytes(contentDecryptor.KeySizeInBytes);

            if (contentDecryptor.TryDecrypt(
                    contentEncryptionKey,
                    new EncryptedData(iv, ciphertext, authTag),
                    aad,
                    out var plaintext))
            {
                // Byte-oriented result: a JWS-wrapping caller (the validator) does the UTF-8 decode.
                return plaintext;
            }
        }

        return new JwtValidationError(
            JwtError.InvalidToken,
            keyFound ? "Failed to decrypt JWE with any available key" : "No decryption keys found");
    }

    /// <summary>
    /// Produces the Content Encryption Key and its wrapped form. Asymmetric key management (RSA, ECDH-ES)
    /// encrypts with the recipient's public half, so it runs in process even for an external key; a symmetric
    /// key whose secret is absent is wrapped by the external custodian; direct and password-based key
    /// management have no external form and fail closed.
    /// </summary>
    private async ValueTask<(byte[] contentEncryptionKey, byte[] encryptedKey)> EncryptKeyAsync(
        JsonWebTokenHeader header,
        JsonWebKey encryptionKey,
        string algorithm,
        int contentKeySizeInBytes,
        CancellationToken cancellationToken)
    {
        // Asymmetric key management (RSA, ECDH-ES) encrypts with the recipient's public half, so it runs in
        // process even for an external key - the public half is present. Only a symmetric key whose secret
        // bytes are absent must be wrapped by the external custodian.
        if (encryptionKey is OctetJsonWebKey { HasPrivateKey: false })
        {
            if (!IsExternallyWrappable(algorithm))
                throw NoExternalForm(encryptionKey, algorithm);

            var port = externalKeyEncryptor ?? throw NoKeyEncryptorPort(encryptionKey);
            var cek = CryptoRandom.GetRandomBytes(contentKeySizeInBytes);
            var wrapped = await port.WrapKeyAsync(RequireKid(encryptionKey), algorithm, header, cek, cancellationToken);
            return (cek, wrapped);
        }

        // In-process dispatch to the keyed primitive.
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
            var keyEncryptor = serviceProvider.GetRequiredKeyedService<IKeyManagementAlgorithm<TJsonWebKey>>(algorithm);
            var cek = keyEncryptor.GenerateContentEncryptionKey(header, jwk, contentKeySizeInBytes);
            return (cek, keyEncryptor.EncryptKey(header, jwk, cek));
        }
    }

    /// <summary>
    /// Recovers the Content Encryption Key from a JWE Encrypted Key. A key with secret material unwraps in
    /// process; a public-only key routes the private operation (RSA decrypt, ECDH agreement, symmetric
    /// unwrap) to an external custodian. Returns null on any decryption failure so a wrong key is
    /// indistinguishable from a bad ciphertext (the RFC 7516 §11.5 mitigation upstream relies on this) and
    /// never throws on the attacker-supplied header.
    /// </summary>
    private async ValueTask<byte[]?> DecryptKeyAsync(
        JsonWebTokenHeader header,
        JsonWebKey decryptionKey,
        string algorithm,
        byte[] encryptedKey,
        CancellationToken cancellationToken)
    {
        // Secret material present: unwrap in process with the keyed primitive (the unchanged path). This
        // branch is the "must have private material" gate.
        if (decryptionKey.HasPrivateKey)
            return DecryptLocally(decryptionKey);

        // Public-only key: route the private operation to the external custodian by kid. Here 'algorithm'
        // and 'kid' come from the attacker-supplied JWE header, so anything this cannot handle returns null
        // and the caller substitutes a random CEK for a uniform failure (RFC 7516 §11.5). A throw would be an
        // oracle or a DoS; a genuinely missing port is a misconfiguration the startup guard rejects at boot,
        // not at request time.
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
            var keyEncryptor = serviceProvider.GetKeyedService<IKeyManagementAlgorithm<TJsonWebKey>>(algorithm);
            return keyEncryptor != null && keyEncryptor.TryDecryptKey(header, jwk, encryptedKey, out var cek)
                ? cek
                : null;
        }
    }

    /// <summary>
    /// External ECDH-ES: the custodian performs the agreement with the recipient's private key and returns
    /// the raw shared secret Z; the Concat KDF and any AES key unwrap run locally. Mirrors the guards of the
    /// in-process EcdhEsKeyEncryptor.TryDecryptKey - only the agreement step is remote.
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

                // Direct Key Agreement: the encrypted key must be empty and the derived key IS the CEK, sized
                // for the content encryption algorithm named by 'enc'.
                if (encryptedKey.Length != 0)
                    return null;

                if (header.EncryptionAlgorithm is not { } contentEncryptionAlgorithm ||
                    serviceProvider.GetKeyedService<IContentEncryptionAlgorithm>(contentEncryptionAlgorithm) is not { } contentEncryptor)
                    return null;

                return ConcatKeyDerivation.DeriveKey(
                    sharedSecretZ,
                    contentEncryptionAlgorithm,
                    apu,
                    apv,
                    contentEncryptor.KeySizeInBytes);
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
