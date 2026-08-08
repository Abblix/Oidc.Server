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
using Abblix.Jwt.ExternalKeys;
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
    /// Adds HSM/KMS/vault handling for public-only keys, wiring one external <see cref="IKeyCustodian"/> into
    /// both crypto seams: a public-only signing key routes its signing to the custodian, and a public-only
    /// decryption key routes its RSA/symmetric unwrap or ECDH-ES agreement to it, while keys that carry their
    /// private/secret material keep working in process. The public operations - signature verification and
    /// wrapping a CEK with the recipient's public half - stay local and never reach the custodian. Call after
    /// <see cref="AddJsonWebTokens"/>; the custodian is DI-constructed, so it can depend on a typed client.
    /// </summary>
    /// <typeparam name="TCustodian">The host custodian implementation.</typeparam>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The service collection, for chaining.</returns>
    /// <remarks>
    /// This is the bare seam: it wires the custodian and nothing else, so the host decides for itself which keys
    /// are public-only and therefore route here. It records no key placement, which makes it the wrong call inside
    /// an OpenID Provider: that server refuses to serve keys once a custodian is registered and no placement was
    /// named, so <c>/jwks</c> and every token issuance would fail. Such a host uses
    /// <see cref="ExternalKeys.ExternalKeysServiceCollectionExtensions.AddCustodian{TCustodian}"/> with a placement
    /// call. Never both: each composes the external backends, and <c>Compose</c> refuses the second composition on
    /// the spot, at the registration call rather than at startup.
    /// </remarks>
    public static IServiceCollection AddKeyCustodian<TCustodian>(this IServiceCollection services)
        where TCustodian : class, IKeyCustodian
    {
        services.TryAddSingleton<IKeyCustodian, TCustodian>();
        return services.ComposeExternalKeyBackends();
    }

    /// <summary>
    /// Adds HSM/KMS/vault handling for public-only keys using a ready <paramref name="custodian"/> instance,
    /// wiring it into both crypto seams. The instance overload suits a pre-built custodian or a test fake; a
    /// custodian that needs DI-resolved dependencies uses <see cref="AddKeyCustodian{TCustodian}"/> instead. See
    /// that overload for the full routing description.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="custodian">The external key custodian serving signing, RSA/symmetric unwrap and ECDH agreement.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddKeyCustodian(this IServiceCollection services, IKeyCustodian custodian)
    {
        services.AddSingleton(custodian);
        return services.ComposeExternalKeyBackends();
    }

    /// <summary>
    /// Adds HSM/KMS/vault handling for public-only keys using a <paramref name="custodianFactory"/> that resolves
    /// the custodian from the container, wiring it into both crypto seams. Suits a custodian that is a typed client
    /// (built from <c>IHttpClientFactory</c>) or otherwise needs DI to construct. The factory runs once, so the
    /// custodian is a singleton. See <see cref="AddKeyCustodian{TCustodian}"/> for the full routing description.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="custodianFactory">Resolves the external key custodian from the service provider.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddKeyCustodian(
        this IServiceCollection services, Func<IServiceProvider, IKeyCustodian> custodianFactory)
    {
        services.AddSingleton(custodianFactory);
        return services.ComposeExternalKeyBackends();
    }

    /// <summary>
    /// Registers <typeparamref name="TBackend"/> into the <typeparamref name="TSeam"/> family, unless that family
    /// has already been composed - which is what the presence of <typeparamref name="TComposite"/> means, the same
    /// test <c>Compose</c> itself uses to refuse a second composition.
    /// </summary>
    private static void AddBackendUnlessComposed<TSeam, TComposite, TBackend>(this IServiceCollection services)
        where TSeam : class
        where TComposite : class, TSeam
        where TBackend : class, TSeam
    {
        if (services.All(descriptor => descriptor.ServiceType != typeof(TComposite)))
            services.TryAddEnumerable(ServiceDescriptor.Singleton<TSeam, TBackend>());
    }

    /// <summary>
    /// Registers the external backends for the wired <see cref="IKeyCustodian"/> - <see cref="ExternalKeySigner"/>
    /// on the signing seam and <see cref="ExternalKeyDecryptor"/> on the key-recovery seam - and composes each
    /// with its in-process peer, so a key routes to the backend that owns it.
    /// </summary>
    public static IServiceCollection ComposeExternalKeyBackends(this IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IDataSigner, ExternalKeySigner>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IContentKeyDecryptor, ExternalKeyDecryptor>());
        services.Compose<IDataSigner, CompositeSigner>();
        return services.Compose<IContentKeyDecryptor, CompositeDecryptor>();
    }

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
        services.TryAddSingleton<IJsonWebTokenCreator, JsonWebTokenCreator>();
        services.TryAddSingleton<IJsonWebTokenValidator, JsonWebTokenValidator>();
        services.TryAddSingleton<IJsonWebTokenEncryptor, JsonWebTokenEncryptor>();
        services.TryAddSingleton<IJsonWebTokenSigner, JsonWebTokenSigner>();

        // The signing seam behind IJsonWebTokenSigner is a composition of key-owning backends (IDataSigner):
        // the in-process LocalKeySigner owns private-bearing keys and is the sole backend by default. A host
        // adds HSM/KMS/vault signing by wiring an IKeyCustodian, which adds an external backend and composes
        // the family; the composite then routes each key to the backend that owns it and fails closed when
        // none does.
        //
        // Skipped once that composition has happened, and this is load-bearing rather than an optimisation.
        // TryAddEnumerable deduplicates against PLAIN descriptors, while a composed family keeps its members as
        // KEYED ones, so the local backend would be added a second time as a plain descriptor sitting beside the
        // composite - and win the singular resolve, silently, because last registration wins. This method is
        // called more than once by design (AddOidcCore and AddSecurityEvents both perform it), so a host that
        // chose a key placement before either of them would lose its external signer with no error anywhere.
        services.AddBackendUnlessComposed<IDataSigner, CompositeSigner, LocalKeySigner>();

        // The key-recovery seam behind IJsonWebTokenEncryptor mirrors the signing seam, including that skip:
        // the in-process LocalKeyDecryptor owns keys that carry their secret half and is the sole backend by
        // default. Encryption (wrapping the CEK) uses the recipient's public half or a local secret and never
        // routes here, so there is no encryptor seam.
        services.AddBackendUnlessComposed<IContentKeyDecryptor, CompositeDecryptor, LocalKeyDecryptor>();

        // Discovery providers project the advertised algorithm sets from the live keyed
        // registrations, so an algorithm the host registers under its own 'alg'/'enc' key is
        // advertised automatically (signing_alg / encryption_alg / encryption_enc values).
        services.TryAddSingleton<SigningAlgorithmsProvider>();
        services.TryAddSingleton<EncryptionAlgorithmsProvider>();

        // Register key encryptors by algorithm.
        // RSA-OAEP and RSA-OAEP-256 are the recommended algorithms; RSA1_5 is opt-in via
        // AddRsaPkcs1KeyManagement (NIST SP 800-131A Rev. 2 disallows PKCS#1 v1.5 key transport).
        services
            .AddKeyManagementAlgorithm<RsaJsonWebKey, RsaKeyEncryptor>(EncryptionAlgorithms.KeyManagement.RsaOaep)
            .AddKeyManagementAlgorithm<RsaJsonWebKey, RsaKeyEncryptor>(EncryptionAlgorithms.KeyManagement.RsaOaep256);

        // AES-GCM Key Wrap (symmetric key encryption with GCM)
        services
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes128Gcmkw)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes192Gcmkw)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesGcmKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes256Gcmkw);

        // AES Key Wrap (RFC 3394 symmetric key wrapping)
        services
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes128KW)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes192KW)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, AesKeyWrapEncryptor>(EncryptionAlgorithms.KeyManagement.Aes256KW);

        // Direct Key Agreement (no key encryption)
        services
            .AddKeyManagementAlgorithm<OctetJsonWebKey, DirectKeyAgreement>(EncryptionAlgorithms.KeyManagement.Dir);

        // ECDH-ES key agreement: direct (the derived key is the CEK) and with RFC 3394 key wrapping
        services
            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(EncryptionAlgorithms.KeyManagement.EcdhEs)
            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW)
            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW)
            .AddKeyManagementAlgorithm<EllipticCurveJsonWebKey, EcdhEsKeyEncryptor>(EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW);

        // Register content encryptors by algorithm
        services
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384)
            .AddContentEncryptor<AesCbcHmacEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes128Gcm)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes192Gcm)
            .AddContentEncryptor<AesGcmEncryptor>(EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

        // Register signers by algorithm.
        // NoneSigner is registered directly: it is the only signer whose constructor takes no
        // algorithm parameter, so the AddSignatureAlgorithm factory (which passes the algorithm as
        // a constructor override) cannot instantiate it.
        services.TryAddKeyedSingleton<ISignatureAlgorithm<JsonWebKey>, NoneSigner>(SigningAlgorithms.None);

        services
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.RS256)
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.RS384)
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.RS512)
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.PS256)
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.PS384)
            .AddSignatureAlgorithm<RsaJsonWebKey, RsaSigner>(SigningAlgorithms.PS512)

            .AddSignatureAlgorithm<EllipticCurveJsonWebKey, EcdsaSigner>(SigningAlgorithms.ES256)
            .AddSignatureAlgorithm<EllipticCurveJsonWebKey, EcdsaSigner>(SigningAlgorithms.ES384)
            .AddSignatureAlgorithm<EllipticCurveJsonWebKey, EcdsaSigner>(SigningAlgorithms.ES512)

            .AddSignatureAlgorithm<OctetJsonWebKey, HmacSigner>(SigningAlgorithms.HS256)
            .AddSignatureAlgorithm<OctetJsonWebKey, HmacSigner>(SigningAlgorithms.HS384)
            .AddSignatureAlgorithm<OctetJsonWebKey, HmacSigner>(SigningAlgorithms.HS512);

        return services;
    }

    /// <summary>
    /// Enables the RSA1_5 (RSAES-PKCS1-v1_5) key management algorithm (RFC 7518 Section 4.2) for
    /// both producing and consuming JWE tokens. It is deliberately not part of
    /// <see cref="AddJsonWebTokens"/>: NIST SP 800-131A Rev. 2 disallows RSA key transport with
    /// PKCS#1 v1.5 padding after 2023, and RFC 8725 §3.2 prescribes preferring RSAES-OAEP -
    /// interoperating with a legacy peer that still requires it is an explicit hosting decision.
    /// The padding's Bleichenbacher decryption oracle stays closed for opted-in hosts by the
    /// RFC 7516 §11.5 mitigation in <see cref="JsonWebTokenEncryptor"/>: a CEK that fails to
    /// decrypt is replaced with a random CEK and the AEAD step still runs, so a decryption
    /// failure is processed identically regardless of padding validity.
    /// </summary>
    /// <param name="services">The service collection to register the encryptor in.</param>
    /// <returns>The service collection for method chaining.</returns>
    public static IServiceCollection AddRsaPkcs1KeyManagement(this IServiceCollection services)
        => services.AddKeyManagementAlgorithm<RsaJsonWebKey, RsaKeyEncryptor>(EncryptionAlgorithms.KeyManagement.Rsa1_5);

    /// <summary>
    /// Enables the PBES2 password-based key management algorithms (PBES2-HS256+A128KW,
    /// PBES2-HS384+A192KW, PBES2-HS512+A256KW; RFC 7518 Section 4.8) for both producing and
    /// consuming JWE tokens. They are deliberately not part of <see cref="AddJsonWebTokens"/>:
    /// the 'p2c' header of an inbound token dictates PBKDF2 work performed before any
    /// authentication of the token (the CVE-2022-36083 class of denial of service), and because
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
            .AddKeyManagementAlgorithm<OctetJsonWebKey, Pbes2KeyEncryptor>(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, Pbes2KeyEncryptor>(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha384Aes192KW)
            .AddKeyManagementAlgorithm<OctetJsonWebKey, Pbes2KeyEncryptor>(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha512Aes256KW);

    /// <summary>
    /// Registers an <see cref="ICriticalHeaderHandler"/> for a single JOSE header extension
    /// parameter listed in a JWS 'crit' array (RFC 7515 §4.1.11). The parameter name is the
    /// DI key, so the registration cannot claim a name without a handler behind it - name and
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
    /// (<see cref="AddSignatureAlgorithm{TKey,TSigner}"/> by 'alg'): one keyed registration serves
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
    /// <typeparam name="TEncryptor">The IKeyManagementAlgorithm implementation for encrypting/decrypting Content Encryption Keys.</typeparam>
    /// <param name="services">The service collection to register the encryptor in.</param>
    /// <param name="algorithm">The JWE key management algorithm identifier (e.g., "RSA-OAEP-256", "A256GCMKW", "dir").</param>
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
    /// <typeparam name="TEncryptor">The IContentEncryptionAlgorithm implementation for encrypting/decrypting JWE content.</typeparam>
    /// <param name="services">The service collection to register the encryptor in.</param>
    /// <param name="algorithm">The JWE content encryption algorithm identifier (e.g., "A256GCM", "A128CBC-HS256").</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the encryptor as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the encryptor constructor via dependency injection override.
    /// Content encryption is performed after the Content Encryption Key (CEK) is encrypted/wrapped by the key encryptor.
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

    /// <summary>
    /// Registers a data signer implementation for a specific JWS signing algorithm.
    /// Signers handle the "alg" parameter in JWS headers (e.g., RS256, ES384, HS512).
    /// </summary>
    /// <typeparam name="TKey">The type of JSON Web Key this signer operates on (RsaJsonWebKey, EllipticCurveJsonWebKey, OctetJsonWebKey, etc.).</typeparam>
    /// <typeparam name="TSigner">The ISignatureAlgorithm implementation for creating/verifying digital signatures.</typeparam>
    /// <param name="services">The service collection to register the signer in.</param>
    /// <param name="algorithm">The JWS signing algorithm identifier (e.g., "RS256", "ES384", "HS512").</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Registers the signer as a keyed singleton service, retrievable by algorithm name.
    /// The algorithm parameter is passed to the signer constructor via dependency injection override.
    /// TryAdd dedups by (service, key) first-wins, so a host pre-registration for the algorithm wins
    /// over the built-in default.
    /// </remarks>
    private static IServiceCollection AddSignatureAlgorithm<TKey, TSigner>(
        this IServiceCollection services,
        string algorithm)
        where TKey: JsonWebKey
        where TSigner: ISignatureAlgorithm<TKey>
    {
        services.TryAddKeyedSingleton<ISignatureAlgorithm<TKey>>(
            algorithm,
            (sp, _) => sp.CreateService<TSigner>(Dependency.Override(algorithm)));
        return services;
    }
}
