// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Abblix.Jwt.Encryption;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using KeyManagement = Abblix.Jwt.EncryptionAlgorithms.KeyManagement;

namespace Abblix.Jwt;

/// <summary>
/// Registers the JWE algorithms: the key-management ones keyed by 'alg' and the content encryptors keyed by 'enc'.
/// </summary>
public static class EncryptionServiceCollectionExtensions
{
    /// <summary>
    /// Registers the key-management algorithms <see cref="ServiceCollectionExtensions.AddJsonWebTokens"/> enables by
    /// default. RSA-OAEP and RSA-OAEP-256 are the recommended RSA algorithms; RSA1_5 and PBES2 are opt-in.
    /// </summary>
    internal static IServiceCollection AddDefaultKeyManagementAlgorithms(this IServiceCollection services)
        => services
            .AddKeyManagementAlgorithm<RsaJsonWebKey, RsaKeyEncryptor>(KeyManagement.RsaOaep)
            .AddKeyManagementAlgorithm<RsaJsonWebKey, RsaKeyEncryptor>(KeyManagement.RsaOaep256)

            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(KeyManagement.Aes128Gcmkw)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(KeyManagement.Aes192Gcmkw)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(KeyManagement.Aes256Gcmkw)

            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesKeyWrapEncryptor>(KeyManagement.Aes128KW)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesKeyWrapEncryptor>(KeyManagement.Aes192KW)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesKeyWrapEncryptor>(KeyManagement.Aes256KW)

            .AddKeyManagementAlgorithm<OctetJsonWebKey, DirectKeyAgreement>(KeyManagement.Dir)

            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(KeyManagement.EcdhEs)
            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(KeyManagement.EcdhEsAes128KW)
            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(KeyManagement.EcdhEsAes192KW)
            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(KeyManagement.EcdhEsAes256KW);

    /// <summary>
    /// Registers the content encryptors <see cref="ServiceCollectionExtensions.AddJsonWebTokens"/> enables by default.
    /// </summary>
    internal static IServiceCollection AddDefaultContentEncryptors(this IServiceCollection services)
        => services
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384)
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes128Gcm)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes192Gcm)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

    /// <summary>
    /// Enables the RSA1_5 (RSAES-PKCS1-v1_5) key management algorithm (RFC 7518 Section 4.2) for
    /// both producing and consuming JWE tokens. It is deliberately not part of
    /// <see cref="ServiceCollectionExtensions.AddJsonWebTokens"/>: NIST SP 800-131A Rev. 2 disallows RSA key
    /// transport with PKCS#1 v1.5 padding after 2023, and RFC 8725 section 3.2 prescribes preferring RSAES-OAEP -
    /// interoperating with a legacy peer that still requires it is an explicit hosting decision.
    /// The padding's Bleichenbacher decryption oracle stays closed for opted-in hosts by the
    /// RFC 7516 section 11.5 mitigation in <see cref="JsonWebTokenEncryptor"/>: a CEK that fails to
    /// decrypt is replaced with a random CEK and the AEAD step still runs, so a decryption
    /// failure is processed identically regardless of padding validity.
    /// </summary>
    /// <param name="services">The service collection to register the encryptor in.</param>
    /// <returns>The service collection for method chaining.</returns>
    public static IServiceCollection AddRsaPkcs1KeyManagement(this IServiceCollection services)
        => services.AddKeyManagementAlgorithm<RsaJsonWebKey, RsaKeyEncryptor>(KeyManagement.Rsa1_5);

    /// <summary>
    /// Enables the PBES2 password-based key management algorithms (PBES2-HS256+A128KW,
    /// PBES2-HS384+A192KW, PBES2-HS512+A256KW; RFC 7518 Section 4.8) for both producing and
    /// consuming JWE tokens. They are deliberately not part of
    /// <see cref="ServiceCollectionExtensions.AddJsonWebTokens"/>: the 'p2c' header of an inbound token
    /// dictates PBKDF2 work performed before any authentication of the token (the CVE-2022-36083 class of
    /// denial of service), and because
    /// JWE decryption keys are matched by key identifier, an octet key configured for another
    /// key-management algorithm could otherwise be driven into the PBKDF2 path by an
    /// attacker-chosen 'alg' header. Accepting password-based key management is therefore an
    /// explicit hosting decision. The iteration count of an inbound token is bounded to
    /// [1000, 10,000] even when enabled.
    /// </summary>
    /// <param name="services">The service collection to register the PBES2 encryptors in.</param>
    /// <returns>The service collection for method chaining.</returns>
    public static IServiceCollection AddPbes2KeyManagement(this IServiceCollection services)
        => services
            .AddKeyManagementAlgorithm<OctetJsonWebKey, Pbes2KeyEncryptor>(KeyManagement.Pbes2HmacSha256Aes128KW)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, Pbes2KeyEncryptor>(KeyManagement.Pbes2HmacSha384Aes192KW)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, Pbes2KeyEncryptor>(KeyManagement.Pbes2HmacSha512Aes256KW);

    /// <summary>
    /// Registers a key encryptor implementation for a specific JWE key management algorithm.
    /// Key encryptors handle the "alg" parameter in JWE headers (e.g., RSA-OAEP, A256GCMKW, dir).
    /// </summary>
    /// <typeparam name="TKey">The type of JSON Web Key this encryptor operates on (RsaJsonWebKey,
    /// OctetJsonWebKey, etc.).</typeparam>
    /// <typeparam name="TEncryptor">The IKeyManagementAlgorithm implementation for encrypting/decrypting Content
    /// Encryption Keys.</typeparam>
    /// <param name="services">The service collection to register the encryptor in.</param>
    /// <param name="algorithm">The JWE key management algorithm identifier (e.g., "RSA-OAEP-256", "A256GCMKW",
    /// "dir").</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the encryptor as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the encryptor constructor via dependency injection override.
    /// TryAdd dedups by (service, key) first-wins, so a host pre-registration for the algorithm wins
    /// over the built-in default.
    /// </remarks>
    private static IServiceCollection AddKeyManagementAlgorithm<TKey, TEncryptor>(
        this IServiceCollection services,
        string algorithm)
        where TKey : JsonWebKey
        where TEncryptor : IKeyManagementAlgorithm<TKey>
    {
        services.TryAddKeyedSingleton<IKeyManagementAlgorithm<TKey>>(
            algorithm,
            (sp, _) => sp.CreateService<TEncryptor>(Dependency.Override(algorithm)));
        return services;
    }

    /// <summary>
    /// Registers a content encryptor implementation for a specific JWE content encryption algorithm.
    /// Content encryptors handle the "enc" parameter in JWE headers (e.g., A256GCM, A128CBC-HS256).
    /// </summary>
    /// <typeparam name="TEncryptor">The IContentEncryptionAlgorithm implementation for encrypting/decrypting JWE
    /// content.</typeparam>
    /// <param name="services">The service collection to register the encryptor in.</param>
    /// <param name="algorithm">The JWE content encryption algorithm identifier (e.g., "A256GCM",
    /// "A128CBC-HS256").</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the encryptor as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the encryptor constructor via dependency injection override.
    /// Content encryption is performed after the Content Encryption Key (CEK) is encrypted/wrapped by the key
    /// encryptor.
    /// TryAdd dedups by (service, key) first-wins, so a host pre-registration for the algorithm wins
    /// over the built-in default.
    /// </remarks>
    private static IServiceCollection AddContentEncryptor<TEncryptor>(
        this IServiceCollection services,
        string algorithm)
        where TEncryptor : IContentEncryptionAlgorithm
    {
        services.TryAddKeyedSingleton<IContentEncryptionAlgorithm>(
            algorithm,
            (sp, _) => sp.CreateService<TEncryptor>(Dependency.Override(algorithm)));
        return services;
    }
}
