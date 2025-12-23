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

        // Register key encryptors by algorithm
        // RSA-based key encryption
        services
            .AddKeyEncryptor<RsaJsonWebKey, RsaKeyEncryptor>(EncryptionAlgorithms.KeyManagement.RsaOaep)
            .AddKeyEncryptor<RsaJsonWebKey, RsaKeyEncryptor>(EncryptionAlgorithms.KeyManagement.RsaOaep256)
            .AddKeyEncryptor<RsaJsonWebKey, RsaKeyEncryptor>(EncryptionAlgorithms.KeyManagement.Rsa1_5);

        // AES-GCM Key Wrap (symmetric key encryption with GCM)
        services
            .AddKeyEncryptor<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes128Gcmkw)
            .AddKeyEncryptor<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes192Gcmkw)
            .AddKeyEncryptor<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes256Gcmkw);

        // Direct Key Agreement (no key encryption)
        services
            .AddKeyEncryptor<OctetJsonWebKey, DirectKeyAgreement>(EncryptionAlgorithms.KeyManagement.Dir);

        // Register content encryptors by algorithm
        services
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384)
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes128Gcm)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes192Gcm)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

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
    /// Registers a key encryptor implementation for a specific JWE key management algorithm.
    /// Key encryptors handle the "alg" parameter in JWE headers (e.g., RSA-OAEP, A256GCMKW, dir).
    /// </summary>
    /// <typeparam name="TKey">The type of JSON Web Key this encryptor operates on (RsaJsonWebKey, OctetJsonWebKey, etc.).</typeparam>
    /// <typeparam name="TEncryptor">The IKeyEncryptor implementation for encrypting/decrypting Content Encryption Keys.</typeparam>
    /// <param name="services">The service collection to register the encryptor in.</param>
    /// <param name="algorithm">The JWE key management algorithm identifier (e.g., "RSA-OAEP-256", "A256GCMKW", "dir").</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the encryptor as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the encryptor constructor via dependency injection override.
    /// </remarks>
    private static IServiceCollection AddKeyEncryptor<TKey, TEncryptor>(
        this IServiceCollection services,
        string algorithm)
        where TKey : JsonWebKey
        where TEncryptor : IKeyEncryptor<TKey>
    {
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
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the encryptor as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the encryptor constructor via dependency injection override.
    /// Content encryption is performed after the Content Encryption Key (CEK) is encrypted/wrapped by the key encryptor.
    /// </remarks>
    private static IServiceCollection AddContentEncryptor<TEncryptor>(
        this IServiceCollection services,
        string algorithm)
        where TEncryptor : IDataEncryptor
    {
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
