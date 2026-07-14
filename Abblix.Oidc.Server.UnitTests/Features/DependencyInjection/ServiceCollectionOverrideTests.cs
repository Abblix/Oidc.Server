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

using System;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;

using Abblix.Jwt;
using Abblix.Jwt.Encryption;
using Abblix.Jwt.Signing;

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.DPoP;
using Abblix.Oidc.Server.Features.RichAuthorizationRequests;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.MinimalApi;

using Microsoft.Extensions.DependencyInjection;

using Moq;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.DependencyInjection;

/// <summary>
/// Verifies that library extension methods honour host pre-registrations: a host that registers
/// a singular contract BEFORE calling an Abblix extension method must still have its implementation
/// win, and an enumerable strategy set must not accumulate duplicate default implementations
/// across repeated invocations.
/// </summary>
public class ServiceCollectionOverrideTests
{
    [Fact]
    public void AddAuthServiceJwt_HostPreregisteredKeysProvider_Wins()
    {
        // Issue #50 canonical example: host pre-registers IAuthServiceKeysProvider.
        var services = new ServiceCollection();
        var stub = new Mock<IAuthServiceKeysProvider>().Object;
        services.AddSingleton<IAuthServiceKeysProvider>(stub);

        services.AddAuthServiceJwt();

        var descriptors = services
            .Where(d => d.ServiceType == typeof(IAuthServiceKeysProvider))
            .ToList();

        Assert.Single(descriptors);
        Assert.Same(stub, descriptors[0].ImplementationInstance);
    }

    [Fact]
    public void AddAuthServiceJwt_InvokedTwice_DefaultsRegisteredOnce()
    {
        // TryAdd* guarantees the library's own default doesn't accumulate on repeated calls.
        var services = new ServiceCollection();

        services.AddAuthServiceJwt();
        services.AddAuthServiceJwt();

        Assert.Single(services, d => d.ServiceType == typeof(IAuthServiceKeysProvider));
        Assert.Single(services, d => d.ServiceType == typeof(IAuthServiceJwtFormatter));
        Assert.Single(services, d => d.ServiceType == typeof(IAuthServiceJwtValidator));
    }

    [Fact]
    public void AddClientAuthentication_InvokedTwice_FailsLoudInsteadOfRecomposing()
    {
        // A compose-family method composes its pipeline exactly once. Invoking it a second time would rebuild a
        // self-referential composite that deadlocks on the first resolve, so the shared Compose guard rejects the
        // second invocation loudly at registration time rather than letting the latent deadlock ship.
        var services = new ServiceCollection();

        services.AddClientAuthentication();

        var ex = Assert.Throws<InvalidOperationException>(() => services.AddClientAuthentication());
        Assert.Contains(nameof(IClientAuthenticator), ex.Message);
    }

    [Fact]
    public void AddDPoP_HostPreregisteredProofValidator_Wins()
    {
        var services = new ServiceCollection();
        var stub = new Mock<IProofValidator>().Object;
        services.AddSingleton<IProofValidator>(stub);

        services.AddDPoP();

        var descriptors = services
            .Where(d => d.ServiceType == typeof(IProofValidator))
            .ToList();

        Assert.Single(descriptors);
        Assert.Same(stub, descriptors[0].ImplementationInstance);
    }

    [Fact]
    public void AddDPoP_InvokedTwice_DefaultsRegisteredOnce()
    {
        var services = new ServiceCollection();

        services.AddDPoP();
        services.AddDPoP();

        Assert.Single(services, d => d.ServiceType == typeof(IProofValidator));
    }

    [Fact]
    public void AddClientInformation_HostPreregisteredClientInfoProvider_Wins()
    {
        // Issue #226: the alias registrations must honor a host pre-registration the same
        // way TryAdd* seams do — "store clients in your own database" is the flagship case.
        var services = new ServiceCollection();
        var stub = new Mock<IClientInfoProvider>().Object;
        services.AddSingleton<IClientInfoProvider>(stub);

        services.AddClientInformation();

        var descriptors = services
            .Where(d => d.ServiceType == typeof(IClientInfoProvider))
            .ToList();

        Assert.Single(descriptors);
        Assert.Same(stub, descriptors[0].ImplementationInstance);
    }

    [Fact]
    public void AddClientInformation_HostPreregisteredClientInfoManager_Wins()
    {
        var services = new ServiceCollection();
        var stub = new Mock<IClientInfoManager>().Object;
        services.AddSingleton<IClientInfoManager>(stub);

        services.AddClientInformation();

        var descriptors = services
            .Where(d => d.ServiceType == typeof(IClientInfoManager))
            .ToList();

        Assert.Single(descriptors);
        Assert.Same(stub, descriptors[0].ImplementationInstance);
    }

    [Fact]
    public void AddAuthorizationEndpoint_HostPreregisteredAuthorizationHandler_Wins()
    {
        var services = new ServiceCollection();
        var stub = new Mock<IAuthorizationHandler>().Object;
        services.AddSingleton<IAuthorizationHandler>(stub);

        services.AddAuthorizationEndpoint();

        var descriptors = services
            .Where(d => d.ServiceType == typeof(IAuthorizationHandler))
            .ToList();

        Assert.Single(descriptors);
        Assert.Same(stub, descriptors[0].ImplementationInstance);
    }

    [Fact]
    public async Task AddAuthServiceJwt_HostStub_ResolvesToStub()
    {
        // End-to-end check: after the library's extension method runs, resolving the contract
        // via the provider returns the host's pre-registered instance.
        var services = new ServiceCollection();
        var stub = new Mock<IAuthServiceKeysProvider>().Object;
        services.AddSingleton<IAuthServiceKeysProvider>(stub);

        services.AddAuthServiceJwt();

        await using var provider = services.BuildServiceProvider();
        var resolved = provider.GetRequiredService<IAuthServiceKeysProvider>();

        Assert.Same(stub, resolved);
    }

    [Fact]
    public void AddOidcMinimalApi_RegistersDefaultAuthSessionService()
    {
        // The MVC transport registers AuthenticationSchemeAdapter as the default IAuthSessionService;
        // the Minimal API transport must mirror it, or a host without its own implementation fails
        // at request time on every endpoint that touches the authentication session.
        var services = new ServiceCollection();

        services.AddOidcMinimalApi();

        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IAuthSessionService));
        Assert.Equal(typeof(AuthenticationSchemeAdapter), descriptor.ImplementationType);
        Assert.Equal(ServiceLifetime.Scoped, descriptor.Lifetime);
    }

    [Fact]
    public void AddOidcMinimalApi_HostPreregisteredAuthSessionService_Wins()
    {
        var services = new ServiceCollection();
        var stub = new Mock<IAuthSessionService>().Object;
        services.AddSingleton(stub);

        services.AddOidcMinimalApi();

        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IAuthSessionService));
        Assert.Same(stub, descriptor.ImplementationInstance);
    }

    [Fact]
    public void AddOidcMinimalApi_EveryEndpointOptedIn_GraphValidates()
    {
        // The full-surface host: every optional endpoint enabled, and the only contract the host
        // itself implements is IUserInfoProvider. ValidateOnBuild constructs every registered
        // descriptor, so a missing default registration anywhere in the adapter or the core
        // fails here instead of surfacing as an HTTP 500 at request time.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddRouting();
        services.AddMemoryCache();
        services.AddDistributedMemoryCache();
        services.AddAuthentication().AddCookie();
        services.AddSingleton(new Mock<IUserInfoProvider>().Object);

        // Grant-bearing opt-ins precede AddOidcMinimalApi so AddOidcCore composes their grant handlers
        services.AddDeviceAuthorization();
        services.AddBackChannelAuthentication();
        services.AddRevocation();
        services.AddIntrospection();
        services.AddCheckSession();
        services.AddDynamicClientRegistration();

        services.AddOidcMinimalApi(_ => { });
        services.AddRichAuthorizationRequests();

        using var provider = services.BuildServiceProvider(
            new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });
    }

    // A signing algorithm the library does not ship (secp256k1); models a host bringing its own signer.
    private const string HostSigningAlgorithm = "ES256K";

    // A key-management algorithm the library does not ship (ECDH-ES); models a host bringing its own encryptor.
    private const string HostKeyManagementAlgorithm = "ECDH-ES";

    [Fact]
    public void AddJsonWebTokens_HostPreregisteredKeyedSigner_Wins()
    {
        // Issue #224: a host pre-registers an alternative signer (e.g. HSM-backed) under a built-in
        // algorithm key. The library registration must not shadow it.
        var services = new ServiceCollection();
        var stub = new HostRsaSigner();
        services.AddKeyedSingleton<IDataSigner<RsaJsonWebKey>>(SigningAlgorithms.RS256, stub);

        services.AddJsonWebTokens();

        var descriptor = Assert.Single(
            services,
            d => d.ServiceType == typeof(IDataSigner<RsaJsonWebKey>) &&
                 Equals(d.ServiceKey, SigningAlgorithms.RS256));
        Assert.Same(stub, descriptor.KeyedImplementationInstance);
    }

    [Fact]
    public void AddJsonWebTokens_HostPreregisteredCreator_Wins()
    {
        var services = new ServiceCollection();
        var stub = new Mock<IJsonWebTokenCreator>().Object;
        services.AddSingleton(stub);

        services.AddJsonWebTokens();

        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IJsonWebTokenCreator));
        Assert.Same(stub, descriptor.ImplementationInstance);
    }

    [Fact]
    public void AddJsonWebTokens_HostPreregisteredSigner_Wins()
    {
        // The signing orchestrator is part of the public JWT surface; a host that fronts an external
        // key custodian may replace it wholesale. The library's TryAdd default must not shadow it.
        var services = new ServiceCollection();
        var stub = new Mock<IJsonWebTokenSigner>().Object;
        services.AddSingleton(stub);

        services.AddJsonWebTokens();

        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IJsonWebTokenSigner));
        Assert.Same(stub, descriptor.ImplementationInstance);
    }

    [Fact]
    public void AddJsonWebTokens_HostPreregisteredEncryptor_Wins()
    {
        // Symmetric with the signer: the encryption orchestrator is public and host-replaceable.
        var services = new ServiceCollection();
        var stub = new Mock<IJsonWebTokenEncryptor>().Object;
        services.AddSingleton(stub);

        services.AddJsonWebTokens();

        var descriptor = Assert.Single(services, d => d.ServiceType == typeof(IJsonWebTokenEncryptor));
        Assert.Same(stub, descriptor.ImplementationInstance);
    }

    [Fact]
    public void AddJsonWebTokens_InvokedTwice_DefaultsRegisteredOnce()
    {
        var services = new ServiceCollection();

        services.AddJsonWebTokens();
        services.AddJsonWebTokens();

        Assert.Single(services, d => d.ServiceType == typeof(IJsonWebTokenCreator));
        Assert.Single(services, d => d.ServiceType == typeof(IJsonWebTokenValidator));
        Assert.Single(
            services,
            d => d.ServiceType == typeof(IDataSigner<RsaJsonWebKey>) &&
                 Equals(d.ServiceKey, SigningAlgorithms.RS256));
        Assert.Single(
            services,
            d => d.ServiceType == typeof(IKeyEncryptor<RsaJsonWebKey>) &&
                 Equals(d.ServiceKey, EncryptionAlgorithms.KeyManagement.RsaOaep256));
    }

    [Fact]
    public void AddJsonWebTokens_HostRegisteredSigningAlgorithm_IsAdvertised()
    {
        // Issue #224: an algorithm the host registers under its own 'alg' key participates in signing,
        // so discovery must advertise it in the *_signing_alg_values_supported lists.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);
        services.AddKeyedSingleton<IDataSigner<EllipticCurveJsonWebKey>>(
            HostSigningAlgorithm, new HostEllipticCurveSigner());

        services.AddJsonWebTokens();

        using var provider = services.BuildServiceProvider();
        Assert.Contains(
            HostSigningAlgorithm,
            provider.GetRequiredService<IJsonWebTokenCreator>().SignedResponseAlgorithmsSupported);
        Assert.Contains(
            HostSigningAlgorithm,
            provider.GetRequiredService<IJsonWebTokenValidator>().SigningAlgorithmsSupported);
    }

    [Fact]
    public void AddJsonWebTokens_HostRegisteredKeyManagementAlgorithm_IsAdvertised()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);
        services.AddKeyedSingleton<IKeyEncryptor<EllipticCurveJsonWebKey>>(
            HostKeyManagementAlgorithm, new HostEllipticCurveKeyEncryptor());

        services.AddJsonWebTokens();

        using var provider = services.BuildServiceProvider();
        Assert.Contains(
            HostKeyManagementAlgorithm,
            provider.GetRequiredService<IJsonWebTokenValidator>().EncryptionAlgorithmsSupported);
    }

    /// <summary>
    /// PBES2 is deliberately absent from the <c>AddJsonWebTokens</c> defaults (the 'p2c' header of an
    /// inbound token dictates pre-authentication PBKDF2 work — the CVE-2022-36083 class of denial of
    /// service), and a host that opts in via <c>AddPbes2KeyManagement</c> gets the family registered
    /// and advertised.
    /// </summary>
    [Fact]
    public void AddPbes2KeyManagement_OptsInPbes2Algorithms()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);

        services.AddPbes2KeyManagement();
        services.AddJsonWebTokens();

        using var provider = services.BuildServiceProvider();
        var advertised = provider.GetRequiredService<IJsonWebTokenValidator>().EncryptionAlgorithmsSupported.ToList();

        Assert.Contains(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW, advertised);
        Assert.Contains(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha384Aes192KW, advertised);
        Assert.Contains(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha512Aes256KW, advertised);
    }

    /// <summary>
    /// RSA1_5 is deliberately absent from the <c>AddJsonWebTokens</c> defaults (NIST SP 800-131A Rev. 2
    /// disallows PKCS#1 v1.5 key transport), and a host interoperating with a legacy peer opts in via
    /// <c>AddRsaPkcs1KeyManagement</c>.
    /// </summary>
    [Fact]
    public void AddRsaPkcs1KeyManagement_OptsInRsa1_5()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);

        services.AddRsaPkcs1KeyManagement();
        services.AddJsonWebTokens();

        using var provider = services.BuildServiceProvider();

        Assert.Contains(
            EncryptionAlgorithms.KeyManagement.Rsa1_5,
            provider.GetRequiredService<IJsonWebTokenValidator>().EncryptionAlgorithmsSupported);
    }

    [Fact]
    public void AddJsonWebTokens_DefaultAlgorithms_AdvertisedInRegistrationOrder()
    {
        // Parity guard for the discovery lists: the advertised defaults keep the exact content and
        // order the accumulate-at-registration providers produced, so published discovery documents
        // do not churn.
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(TimeProvider.System);

        services.AddJsonWebTokens();

        using var provider = services.BuildServiceProvider();

        Assert.Equal(
            [
                SigningAlgorithms.None,
                SigningAlgorithms.RS256, SigningAlgorithms.RS384, SigningAlgorithms.RS512,
                SigningAlgorithms.PS256, SigningAlgorithms.PS384, SigningAlgorithms.PS512,
                SigningAlgorithms.ES256, SigningAlgorithms.ES384, SigningAlgorithms.ES512,
                SigningAlgorithms.HS256, SigningAlgorithms.HS384, SigningAlgorithms.HS512,
            ],
            provider.GetRequiredService<IJsonWebTokenCreator>().SignedResponseAlgorithmsSupported);

        var validator = provider.GetRequiredService<IJsonWebTokenValidator>();
        Assert.Equal(
            [
                EncryptionAlgorithms.KeyManagement.RsaOaep,
                EncryptionAlgorithms.KeyManagement.RsaOaep256,
                EncryptionAlgorithms.KeyManagement.EcdhEs,
                EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW,
                EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW,
                EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW,
                EncryptionAlgorithms.KeyManagement.Aes128Gcmkw,
                EncryptionAlgorithms.KeyManagement.Aes192Gcmkw,
                EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
                EncryptionAlgorithms.KeyManagement.Aes128KW,
                EncryptionAlgorithms.KeyManagement.Aes192KW,
                EncryptionAlgorithms.KeyManagement.Aes256KW,
                EncryptionAlgorithms.KeyManagement.Dir,
            ],
            validator.EncryptionAlgorithmsSupported);
        Assert.Equal(
            [
                EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256,
                EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384,
                EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512,
                EncryptionAlgorithms.ContentEncryption.Aes128Gcm,
                EncryptionAlgorithms.ContentEncryption.Aes192Gcm,
                EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
            ],
            validator.EncryptionMethodsSupported);
    }

    private sealed class HostRsaSigner : IDataSigner<RsaJsonWebKey>
    {
        public string Algorithm => SigningAlgorithms.RS256;

        public byte[] Sign(RsaJsonWebKey key, byte[] data) => [];

        public bool Verify(RsaJsonWebKey key, byte[] data, byte[] signature) => false;
    }

    private sealed class HostEllipticCurveSigner : IDataSigner<EllipticCurveJsonWebKey>
    {
        public string Algorithm => HostSigningAlgorithm;

        public byte[] Sign(EllipticCurveJsonWebKey key, byte[] data) => [];

        public bool Verify(EllipticCurveJsonWebKey key, byte[] data, byte[] signature) => false;
    }

    private sealed class HostEllipticCurveKeyEncryptor : IKeyEncryptor<EllipticCurveJsonWebKey>
    {
        public string Algorithm => HostKeyManagementAlgorithm;

        public byte[] EncryptKey(JsonWebTokenHeader header, EllipticCurveJsonWebKey encryptionKey, byte[] keyToEncrypt)
            => [];

        public bool TryDecryptKey(
            JsonWebTokenHeader header,
            EllipticCurveJsonWebKey decryptingKey,
            byte[] encryptedKey,
            [NotNullWhen(true)] out byte[]? decryptedKey)
        {
            decryptedKey = null;
            return false;
        }
    }
}
