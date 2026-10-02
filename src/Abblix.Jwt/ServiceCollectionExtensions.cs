// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
    /// Registers the external backends for the wired <see cref="IKeyCustodian"/> - <see cref="ExternalKeySigner"/>
    /// on the signing seam and <see cref="ExternalKeyDecryptor"/> on the key-recovery seam - and composes each
    /// with its in-process peer, so a key routes to the backend that owns it: a public-only signing key routes its
    /// signing to the custodian, a public-only decryption key routes its unwrap or ECDH-ES agreement there, and
    /// keys carrying their private material keep working in process.
    /// </summary>
    /// <remarks>
    /// The raw seam, for a host that manages key material entirely on its own terms. It records no key placement,
    /// which makes it the wrong call inside an OpenID Provider: that server refuses to serve keys once a custodian
    /// is registered and no placement was named, so <c>/jwks</c> and every token issuance would fail. Such a host
    /// calls <see cref="ExternalKeys.ExternalKeysServiceCollectionExtensions.AddCustodian{TCustodian}"/> and a
    /// placement, which perform this too. Never both: <c>Compose</c> refuses the second composition on the spot.
    /// <para>
    /// Call after <see cref="AddJsonWebTokens"/>, whose in-process backends this composes with. Register the
    /// custodian first, by any means the container accepts - it is resolved, not passed in here.
    /// </para>
    /// </remarks>
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
        // Placed through the family cursor rather than TryAddEnumerable, because this method is called more
        // than once by design - the OIDC registration performs it, and so does the security-event one - so a
        // host may well have composed the family in between. TryAddEnumerable dedupes against plain
        // descriptors and a composed family is keyed, so it would leave a second copy beside the composite
        // that silently wins the resolve.
        services.Decompose<IDataSigner>().AddLast(ServiceDescriptor.Singleton<IDataSigner, LocalKeySigner>());

        // The key-recovery seam behind IJsonWebTokenEncryptor mirrors the signing seam in every respect: the
        // in-process LocalKeyDecryptor owns keys that carry their secret half and is the sole backend by default.
        // Encryption (wrapping the CEK) uses the recipient's public half or a local secret and never routes here,
        // so there is no encryptor seam.
        services.Decompose<IContentKeyDecryptor>()
            .AddLast(ServiceDescriptor.Singleton<IContentKeyDecryptor, LocalKeyDecryptor>());

        // Discovery providers project the advertised algorithm sets from the live keyed
        // registrations, so an algorithm the host registers under its own 'alg'/'enc' key is
        // advertised automatically (signing_alg / encryption_alg / encryption_enc values).
        services.TryAddSingleton<SigningAlgorithmsProvider>();
        services.TryAddSingleton<EncryptionAlgorithmsProvider>();

        return services
            .AddDefaultKeyManagementAlgorithms()
            .AddDefaultContentEncryptors()
            .AddDefaultSignatureAlgorithms();
    }

    /// <summary>
    /// Registers an <see cref="ICriticalHeaderHandler"/> for a single JOSE header extension
    /// parameter listed in a JWS 'crit' array (RFC 7515 section 4.1.11). The parameter name is the
    /// DI key, so the registration cannot claim a name without a handler behind it - name and
    /// behavior are inseparable.
    /// </summary>
    /// <typeparam name="THandler">Concrete handler type.</typeparam>
    /// <param name="services">The service collection to register the handler in.</param>
    /// <param name="headerName">The JOSE header parameter name the handler implements
    /// (byte-exact per RFC 7515 section 5.3); used as the DI key the validator routes a 'crit' name
    /// to. A handler covering a family of related names registers under each.</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// Keyed-name DI mirrors the signer/encryptor registrations in this assembly
    /// (<see cref="SigningServiceCollectionExtensions.AddSignatureAlgorithm{TKey,TSigner}"/> by 'alg'): one keyed
    /// registration serves O(1) request-time dispatch (<c>GetKeyedService&lt;ICriticalHeaderHandler&gt;(name)</c>).
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
}
