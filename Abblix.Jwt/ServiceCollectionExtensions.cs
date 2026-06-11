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

using Abblix.DependencyInjection;
using Abblix.Jwt.Encryption;
using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Jwt;

/// <summary>
/// Provides extension methods for <see cref="IServiceCollection"/> to register JwT-related services within the application.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers services for creating and validating JSON Web Tokens (JWTs) within the application.
    /// </summary>
    /// <remarks>
    /// This method adds services for JWT handling, enabling the application to generate and validate JWTs efficiently.
    /// JWTs are an essential part of modern web application security, used for representing claims securely between
    /// two parties.
    ///
    /// By registering these services, the application can:
    /// - Create JWTs with <see cref="IJsonWebTokenCreator"/>, allowing for the generation of tokens that can securely
    /// transmit information between parties.
    /// - Validate JWTs with <see cref="IJsonWebTokenValidator"/>, ensuring that incoming tokens are valid and
    /// have not been tampered with.
    ///
    /// This setup is crucial for implementing authentication and authorization mechanisms that rely on JWTs,
    /// such as OAuth 2.0 and OpenID Connect.
    /// </remarks>
    /// <param name="services">The <see cref="IServiceCollection"/> to configure with JWT services.</param>
    /// <returns>The configured <see cref="IServiceCollection"/>, enabling further chaining of service registrations.</returns>
    public static IServiceCollection AddJsonWebTokens(this IServiceCollection services)
    {
        services
            .AddSingleton<IJsonWebTokenCreator, JsonWebTokenCreator>()
            .AddSingleton<IJsonWebTokenValidator, JsonWebTokenValidator>()
            .AddSingleton<IJsonWebTokenEncryptor, JsonWebTokenEncryptor>()
            .AddSingleton<IJsonWebTokenSigner, JsonWebTokenSigner>();

        // Tracks the registered JWE algorithms for discovery (request_object_encryption_*_values_supported).
        var encryptionAlgorithmsProvider = new EncryptionAlgorithmsProvider();

        // Register key encryptors by algorithm.
        // RSA-OAEP and RSA-OAEP-256 are the recommended algorithms. RSA1_5 (RSAES-PKCS1-v1_5) is
        // kept for backward compatibility despite RFC 8725 §3.2's advice to prefer RSAES-OAEP: its
        // padding would otherwise make the decryption endpoint a Bleichenbacher oracle. That oracle
        // is closed in JsonWebTokenEncryptor.DecryptAsync by the RFC 7516 §11.5 mitigation — a CEK
        // that fails to decrypt is replaced with a random CEK and the AEAD step still runs, so a
        // decryption failure is processed identically regardless of padding validity.
        services
            .AddKeyEncryptor<RsaJsonWebKey, RsaKeyEncryptor>(EncryptionAlgorithms.KeyManagement.RsaOaep, encryptionAlgorithmsProvider)
            .AddKeyEncryptor<RsaJsonWebKey, RsaKeyEncryptor>(EncryptionAlgorithms.KeyManagement.RsaOaep256, encryptionAlgorithmsProvider)
            .AddKeyEncryptor<RsaJsonWebKey, RsaKeyEncryptor>(EncryptionAlgorithms.KeyManagement.Rsa1_5, encryptionAlgorithmsProvider);

        // AES-GCM Key Wrap (symmetric key encryption with GCM)
        services
            .AddKeyEncryptor<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes128Gcmkw, encryptionAlgorithmsProvider)
            .AddKeyEncryptor<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes192Gcmkw, encryptionAlgorithmsProvider)
            .AddKeyEncryptor<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes256Gcmkw, encryptionAlgorithmsProvider);

        // Direct Key Agreement (no key encryption)
        services
            .AddKeyEncryptor<OctetJsonWebKey, DirectKeyAgreement>(EncryptionAlgorithms.KeyManagement.Dir, encryptionAlgorithmsProvider);

        // Register content encryptors by algorithm
        services
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256, encryptionAlgorithmsProvider)
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384, encryptionAlgorithmsProvider)
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512, encryptionAlgorithmsProvider)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes128Gcm, encryptionAlgorithmsProvider)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes192Gcm, encryptionAlgorithmsProvider)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes256Gcm, encryptionAlgorithmsProvider);

        services.AddSingleton(encryptionAlgorithmsProvider);

        // Register signers by algorithm
        var signingAlgorithmsProvider = new SigningAlgorithmsProvider();

        services
            .AddDataSigner<JsonWebKey, NoneSigner>(SigningAlgorithms.None, signingAlgorithmsProvider)

            .AddDataSigner<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.RS256, signingAlgorithmsProvider)
            .AddDataSigner<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.RS384, signingAlgorithmsProvider)
            .AddDataSigner<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.RS512, signingAlgorithmsProvider)
            .AddDataSigner<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.PS256, signingAlgorithmsProvider)
            .AddDataSigner<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.PS384, signingAlgorithmsProvider)
            .AddDataSigner<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.PS512, signingAlgorithmsProvider)

            .AddDataSigner<EllipticCurveJsonWebKey, EcdsaSigner>(SigningAlgorithms.ES256, signingAlgorithmsProvider)
            .AddDataSigner<EllipticCurveJsonWebKey, EcdsaSigner>(SigningAlgorithms.ES384, signingAlgorithmsProvider)
            .AddDataSigner<EllipticCurveJsonWebKey, EcdsaSigner>(SigningAlgorithms.ES512, signingAlgorithmsProvider)

            .AddDataSigner<OctetJsonWebKey, HmacSigner>(SigningAlgorithms.HS256, signingAlgorithmsProvider)
            .AddDataSigner<OctetJsonWebKey, HmacSigner>(SigningAlgorithms.HS384, signingAlgorithmsProvider)
            .AddDataSigner<OctetJsonWebKey, HmacSigner>(SigningAlgorithms.HS512, signingAlgorithmsProvider)

            .AddSingleton(signingAlgorithmsProvider);

        return services;
    }

    /// <summary>
    /// Registers an <see cref="ICriticalHeaderHandler"/> for a single JOSE header extension
    /// parameter listed in a JWS 'crit' array (RFC 7515 §4.1.11). The parameter name is the
    /// DI key, so the registration cannot claim a name without a handler behind it — name and
    /// behaviour are inseparable.
    /// </summary>
    /// <typeparam name="THandler">Concrete handler type.</typeparam>
    /// <param name="services">The service collection to register the handler in.</param>
    /// <param name="headerName">The JOSE header parameter name the handler implements
    /// (byte-exact per RFC 7515 §5.3); used as the DI key the validator routes a 'crit' name
    /// to. A handler covering a family of related names registers under each.</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Keyed-name DI mirrors the signer/encryptor registrations in this assembly
    /// (<see cref="AddDataSigner{TKey,TSigner}"/> by 'alg'): one keyed registration serves
    /// O(1) request-time dispatch (<c>GetKeyedService&lt;ICriticalHeaderHandler&gt;(name)</c>).
    /// <see cref="ServiceCollectionDescriptorExtensions.TryAddKeyedSingleton{TService,TImplementation}(IServiceCollection,object)"/>
    /// dedups by (service, key) first-wins, so a host pre-registration for a name wins over a
    /// later default.
    /// </remarks>
    public static IServiceCollection AddCriticalHeaderHandler<THandler>(
        this IServiceCollection services,
        string headerName)
        where THandler : class, ICriticalHeaderHandler
    {
        services.TryAddKeyedSingleton<ICriticalHeaderHandler, THandler>(headerName);
        return services;
    }

    /// <summary>
    /// Registers a key encryptor implementation for a specific JWE key management algorithm.
    /// Key encryptors handle the "alg" parameter in JWE headers (e.g., RSA-OAEP, A256GCMKW, dir).
    /// </summary>
    /// <typeparam name="TKey">The type of JSON Web Key this encryptor operates on (RsaJsonWebKey, OctetJsonWebKey, etc.).</typeparam>
    /// <typeparam name="TEncryptor">The IKeyEncryptor implementation for encrypting/decrypting Content Encryption Keys.</typeparam>
    /// <param name="services">The service collection to register the encryptor in.</param>
    /// <param name="algorithm">The JWE key management algorithm identifier (e.g., "RSA-OAEP-256", "A256GCMKW", "dir").</param>
    /// <param name="encryptionAlgorithmsProvider">Accumulates the registered algorithm for discovery advertisement.</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the encryptor as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the encryptor constructor via dependency injection override.
    /// </remarks>
    private static IServiceCollection AddKeyEncryptor<TKey, TEncryptor>(
        this IServiceCollection services,
        string algorithm,
        EncryptionAlgorithmsProvider encryptionAlgorithmsProvider)
        where TKey : JsonWebKey
        where TEncryptor : IKeyEncryptor<TKey>
    {
        encryptionAlgorithmsProvider.AddKeyManagement(algorithm);

        return services.AddKeyedSingleton<IKeyEncryptor<TKey>>(
            algorithm,
            (sp, _) => sp.CreateService<TEncryptor>(Dependency.Override(algorithm)));
    }

    /// <summary>
    /// Registers a content encryptor implementation for a specific JWE content encryption algorithm.
    /// Content encryptors handle the "enc" parameter in JWE headers (e.g., A256GCM, A128CBC-HS256).
    /// </summary>
    /// <typeparam name="TEncryptor">The IDataEncryptor implementation for encrypting/decrypting JWE content.</typeparam>
    /// <param name="services">The service collection to register the encryptor in.</param>
    /// <param name="algorithm">The JWE content encryption algorithm identifier (e.g., "A256GCM", "A128CBC-HS256").</param>
    /// <param name="encryptionAlgorithmsProvider">Accumulates the registered algorithm for discovery advertisement.</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the encryptor as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the encryptor constructor via dependency injection override.
    /// Content encryption is performed after the Content Encryption Key (CEK) is encrypted/wrapped by the key encryptor.
    /// </remarks>
    private static IServiceCollection AddContentEncryptor<TEncryptor>(
        this IServiceCollection services,
        string algorithm,
        EncryptionAlgorithmsProvider encryptionAlgorithmsProvider)
        where TEncryptor : IDataEncryptor
    {
        encryptionAlgorithmsProvider.AddContentEncryption(algorithm);

        return services.AddKeyedSingleton<IDataEncryptor>(
            algorithm,
            (sp, _) => sp.CreateService<TEncryptor>(Dependency.Override(algorithm)));
    }

    /// <summary>
    /// Registers a data signer implementation for a specific JWS signing algorithm.
    /// Signers handle the "alg" parameter in JWS headers (e.g., RS256, ES384, HS512).
    /// </summary>
    /// <typeparam name="TKey">The type of JSON Web Key this signer operates on (RsaJsonWebKey, EllipticCurveJsonWebKey, OctetJsonWebKey, etc.).</typeparam>
    /// <typeparam name="TSigner">The IDataSigner implementation for creating/verifying digital signatures.</typeparam>
    /// <param name="services">The service collection to register the signer in.</param>
    /// <param name="algorithm">The JWS signing algorithm identifier (e.g., "RS256", "ES384", "HS512").</param>
    /// <param name="signingAlgorithmsProvider">The provider that tracks all registered signing algorithms for discovery.</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the signer as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the signer constructor via dependency injection override.
    /// Additionally registers the algorithm in the provider for algorithm discovery by consumers.
    /// </remarks>
    private static IServiceCollection AddDataSigner<TKey, TSigner>(
        this IServiceCollection services,
        string algorithm,
        SigningAlgorithmsProvider signingAlgorithmsProvider)
        where TKey: JsonWebKey
        where TSigner: IDataSigner<TKey>
    {
        signingAlgorithmsProvider.Add(algorithm);

        return services.AddKeyedSingleton<IDataSigner<TKey>>(
            algorithm,
            (sp, _) => sp.CreateService<TSigner>(Dependency.Override(algorithm)));
    }
}
