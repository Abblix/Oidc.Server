// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading.RateLimiting;
using System.Threading.Tasks;
using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// What <see cref="MultiTenancyExtensions.AddMultiTenancy"/> puts in the container, the issuer a request gets
/// through it, and the tenant lists startup refuses.
/// </summary>
public class MultiTenancyRegistrationTests
{
    private const string AcmeIssuer = "https://auth.example.com/tenants/acme";

    private static readonly TenantDefinition Acme = new() { Id = "acme", Issuer = AcmeIssuer };

    private static ServiceProvider BuildProvider()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();

        // The library's own issuer registration, not a stand-in, since it is what AddMultiTenancy has to win over.
        services.AddIssuer();
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));

        return services.BuildServiceProvider();
    }

    private static void EnterTenant(IServiceProvider provider, TenantDefinition? tenant)
    {
        var context = new DefaultHttpContext();
        if (tenant is not null)
            context.Features.Set(new TenantContext { Tenant = tenant });

        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
    }

    [Fact]
    public void UnderATenant_TheIssuerIsTheOneItDeclares()
    {
        using var provider = BuildProvider();
        EnterTenant(provider, Acme);

        Assert.Equal(AcmeIssuer, provider.GetRequiredService<IIssuerProvider>().GetIssuer());
    }

    /// <summary>
    /// Multi-tenancy keeps each tenant's data apart by wrapping the storage the server registered, so a call
    /// placed before that storage would leave it shared - it is refused, naming the order.
    /// </summary>
    [Fact]
    public void AddMultiTenancy_BeforeTheServersStorage_IsRefused()
    {
        var services = new ServiceCollection();

        var refusal = Assert.Throws<InvalidOperationException>(
            () => services.AddMultiTenancy(options => options.Tenants.Add(Acme)));
        Assert.Contains("after AddOidcServices()", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The refusal names each service it finds missing, the per-caller budgets registered under a key included:
    /// storage in place but client authentication not yet registered is still the wrong order.
    /// </summary>
    [Fact]
    public void AddMultiTenancy_BeforeTheFailureBudget_IsRefused_NamingIt()
    {
        var services = new ServiceCollection()
            .AddLogging()
            .AddDistributedMemoryCache()
            .AddCommonServices()
            .AddReplayPrevention();

        var refusal = Assert.Throws<InvalidOperationException>(
            () => services.AddMultiTenancy(options => options.Tenants.Add(Acme)));
        Assert.Contains(CallerRateLimiters.AuthenticationFailures, refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A second call would wrap the storage again and change every key it holds, losing what was stored
    /// before, so it is refused.
    /// </summary>
    [Fact]
    public void ASecondCallToAddMultiTenancy_IsRefused()
    {
        var services = new ServiceCollection().AddServerStorage();
        services.AddMultiTenancy(options => options.Tenants.Add(Acme));

        var refusal = Assert.Throws<InvalidOperationException>(
            () => services.AddMultiTenancy(options => options.Tenants.Add(Acme)));
        Assert.Contains("already", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A host wrapping the storage itself after multi-tenancy is refused too, and told what to move rather than
    /// that something replaced the storage.
    /// </summary>
    [Fact]
    public void AStorageDecoratedAfterMultiTenancy_IsRefused_NamingTheOrder()
    {
        var services = new ServiceCollection().AddServerStorage();
        services.AddMultiTenancy(options => options.Tenants.Add(Acme));
        services.Decorate<IEntityStorage, PassThroughStorage>();
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains("registered or decorated after", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>A host's own storage wrapper, adding nothing.</summary>
    private sealed class PassThroughStorage(IEntityStorage inner) : IEntityStorage
    {
        public Task SetAsync<T>(string key, T value, StorageOptions options, System.Threading.CancellationToken? token = null)
            => inner.SetAsync(key, value, options, token);

        public Task<T?> GetAsync<T>(string key, bool removeOnRetrieval, System.Threading.CancellationToken? token = null)
            => inner.GetAsync<T>(key, removeOnRetrieval, token);

        public Task<bool> TrySetIfAbsentAsync<T>(
            string key, T value, StorageOptions options, System.Threading.CancellationToken? token = null)
            => inner.TrySetIfAbsentAsync(key, value, options, token);

        public Task RemoveAsync(string key, System.Threading.CancellationToken? token = null)
            => inner.RemoveAsync(key, token);
    }

    /// <summary>
    /// A tenant's pairwise key that cannot seal is refused at startup, naming the tenant, rather than by a 500 the
    /// first time one of its clients is given a pairwise identifier.
    /// </summary>
    [Fact]
    public void ATenantsUnusablePairwiseKey_IsRefusedAtStartup()
    {
        var tooShort = new TenantDefinition
        {
            Id = "acme",
            Issuer = AcmeIssuer,
            PairwiseSubject = new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[16]) },
        };
        var services = new ServiceCollection().AddServerStorage();
        services.AddMultiTenancy(options => options.Tenants.Add(tooShort));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains("Tenant 'acme': The pairwise salt must decode to at least", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A pairwise key registered for the whole server would be ignored under multi-tenancy, so startup refuses it.
    /// </summary>
    [Fact]
    public void AServerWidePairwiseKey_IsRefusedAtStartup()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddPairwiseSubjectIdentifiers(new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) });
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains($"A {nameof(PairwiseSubjectSettings)} registered for the whole server", refusal.Message,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A container serving keys from each tenant's settings, as a host that keeps its keys in configuration has.
    /// </summary>
    private static ServiceProvider KeysFromSettings(TenantDefinition tenant, Action<OidcOptions>? configure = null)
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options => configure?.Invoke(options));
        services.AddIssuer();
        services.AddAuthServiceJwt();
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(tenant));
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// A tenant whose keys come from its settings and that declares none to sign with is refused at startup, naming
    /// the tenant, rather than issuing no token and publishing an empty JWKS.
    /// </summary>
    [Fact]
    public void ATenantWithoutASigningKey_IsRefusedAtStartup()
    {
        using var provider = KeysFromSettings(Acme);

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains("Tenant 'acme': No signing key is declared", refusal.Message, StringComparison.Ordinal);
        Assert.Contains($"{nameof(TenantDefinition)}.{nameof(TenantDefinition.SigningKeys)}", refusal.Message,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A tenant with no key to encrypt a service token the server's settings ask to encrypt is refused at startup,
    /// naming the tenant and the token.
    /// </summary>
    [Fact]
    public void ATenantWithoutAnEncryptionKey_IsRefused_WhenAServiceTokenIsEncrypted()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddOidcCore(options => options.ServiceTokens.AccessToken.Encrypt = true);
        services.AddMultiTenancy(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "acme",
            Issuer = AcmeIssuer,
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        }));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains(
            "Tenant 'acme': ServiceTokens.AccessToken.Encrypt is true, but no encryption key is available: " +
            $"{nameof(TenantDefinition)}.{nameof(TenantDefinition.EncryptionKeys)} is empty",
            refusal.Message,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A tenant declaring its keys starts, and the server's own settings, which under multi-tenancy carry none, are
    /// not refused for it by any of the server's checks.
    /// </summary>
    [Fact]
    public void ATenantWithItsKeys_Starts()
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddOidcCore(options => options.ServiceTokens.AccessToken.Encrypt = true);
        services.AddMultiTenancy(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "acme",
            Issuer = AcmeIssuer,
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
            EncryptionKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption)],
        }));
        using var provider = services.BuildServiceProvider();

        Assert.NotEmpty(provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants);
        Assert.NotNull(provider.GetRequiredService<IOptions<OidcOptions>>().Value);
    }

    /// <summary>
    /// Each tenant decrypts with its own encryption keys only, so a token encrypted to one tenant is read there and
    /// by no other.
    /// </summary>
    [Fact]
    public async Task ATokenEncryptedToOneTenant_IsReadThere_AndByNoOther()
    {
        TenantDefinition TenantWithKeys(string id) => new()
        {
            Id = id,
            Issuer = $"https://auth.example.com/tenants/{id}",
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
            EncryptionKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption)],
        };

        var acme = TenantWithKeys("acme");
        var globex = TenantWithKeys("globex");
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddAuthServiceJwt();
        services.AddServerStorage().AddMultiTenancy(options =>
        {
            options.Tenants.Add(acme);
            options.Tenants.Add(globex);
        });
        using var provider = services.BuildServiceProvider();

        EnterTenant(provider, acme);
        var encrypted = await provider.GetRequiredService<IAuthServiceJwtFormatter>().FormatAsync(
            new JsonWebToken
            {
                Header = { Algorithm = SigningAlgorithms.RS256 },
                Payload = { Subject = "user123", Issuer = acme.Issuer },
            },
            new ServiceJwtEncryption(
                Encrypt: true,
                EncryptionAlgorithms.KeyManagement.RsaOaep256,
                KeyId: null,
                EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512));

        var atAcme = await ReadAsync();
        Assert.True(atAcme.TryGetSuccess(out _), atAcme.TryGetFailure(out var failure) ? failure.ErrorDescription : null);
        EnterTenant(provider, globex);
        var atGlobex = await ReadAsync();
        Assert.True(atGlobex.TryGetFailure(out var refusal), "Another tenant read the token.");
        Assert.Contains("decryption", refusal.ErrorDescription, StringComparison.OrdinalIgnoreCase);

        // Read as the tenant current in the container, with the keys it decrypts and verifies with
        Task<Result<JsonWebToken, JwtValidationError>> ReadAsync()
        {
            var keys = provider.GetRequiredService<IAuthServiceKeysProvider>();
            return provider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(
                encrypted,
                new ValidationParameters
                {
                    Options = ValidationOptions.RequireValidSignedTokens,
                    ResolveIssuerSigningKeys = _ => keys.GetSigningKeys(),
                    ResolveTokenDecryptionKeys = _ => keys.GetEncryptionKeys(true),
                });
        }
    }

    /// <summary>
    /// Each tenant decrypts with its own encryption keys only, so what a client encrypted to one tenant no other can
    /// read, and signs with its own signing keys.
    /// </summary>
    [Fact]
    public async Task EachTenant_DecryptsAndSignsWithItsOwnKeysOnly()
    {
        TenantDefinition TenantWithKeys(string id) => new()
        {
            Id = id,
            Issuer = $"https://auth.example.com/tenants/{id}",
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature) with { KeyId = $"{id}-sig" }],
            EncryptionKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption) with { KeyId = $"{id}-enc" }],
        };

        var acme = TenantWithKeys("acme");
        var globex = TenantWithKeys("globex");
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddAuthServiceJwt();
        services.AddServerStorage().AddMultiTenancy(options =>
        {
            options.Tenants.Add(acme);
            options.Tenants.Add(globex);
        });
        using var provider = services.BuildServiceProvider();
        var keys = provider.GetRequiredService<IAuthServiceKeysProvider>();
        var ct = TestContext.Current.CancellationToken;

        EnterTenant(provider, acme);
        var acmeDecrypts = await keys.GetEncryptionKeys(includePrivateKeys: true).ToArrayAsync(ct);
        var acmeSigns = await keys.GetSigningKeys(includePrivateKeys: true).ToArrayAsync(ct);
        EnterTenant(provider, globex);
        var globexDecrypts = await keys.GetEncryptionKeys(includePrivateKeys: true).ToArrayAsync(ct);

        Assert.Equal("acme-enc", Assert.Single(acmeDecrypts).KeyId);
        Assert.Equal("acme-sig", Assert.Single(acmeSigns).KeyId);
        Assert.Equal("globex-enc", Assert.Single(globexDecrypts).KeyId);
    }

    /// <summary>
    /// Keys held by a custodian do not come from a tenant's settings, so none are demanded of them.
    /// </summary>
    [Fact]
    public void KeysHeldByACustodian_AreNotDemandedOfATenantsSettings()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddAuthServiceJwt();
        services.AddSingleton(Moq.Mock.Of<IKeyCustodian>());
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        Assert.NotEmpty(provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants);
    }

    private static TenantDefinition NamingInTheCustodian(string id, string signingKeyName) => new()
    {
        Id = id,
        Issuer = $"https://auth.example.com/tenants/{id}",
        CustodianKeys = new CustodianHeldKeys { SigningKeyName = signingKeyName },
    };

    /// <summary>
    /// A container keeping its keys in a custodian that publishes, under each key name, a key whose id is the name.
    /// </summary>
    private static ServiceProvider KeysInACustodian(
        IEnumerable<TenantDefinition> tenants,
        CustodianHeldKeys? serverWideKeys = null)
    {
        var custodian = new Moq.Mock<IKeyCustodian>();
        custodian
            .Setup(c => c.GetKeyVersionsAsync(Moq.It.IsAny<string>(), Moq.It.IsAny<CancellationToken>()))
            .Returns((string keyName, CancellationToken _) =>
            {
                using var rsa = RSA.Create(2048);
                var key = new RsaJsonWebKey().Apply(rsa.ExportParameters(false)) with { KeyId = keyName };
                return new[] { new KeyVersion(key, DateTimeOffset.MinValue) }.ToAsyncEnumerable();
            });

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton(custodian.Object);
        services.AddJsonWebTokens();
        services.AddIssuer();
        services.AddAuthServiceJwt();
        if (serverWideKeys is null)
            services.RequireKeyPlacement().UseKeysInCustodian();
        else
            services.RequireKeyPlacement().UseKeysInCustodian(serverWideKeys);
        services.AddServerStorage().AddMultiTenancy(options =>
        {
            foreach (var tenant in tenants)
                options.Tenants.Add(tenant);
        });
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// With the keys held by a custodian, each tenant produces with the keys it names there.
    /// </summary>
    [Fact]
    public async Task EachTenant_PublishesTheCustodianKeysItNames()
    {
        var acme = NamingInTheCustodian("acme", "acme-sign");
        var globex = NamingInTheCustodian("globex", "globex-sign");
        using var provider = KeysInACustodian([acme, globex]);
        Assert.NotEmpty(provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants);
        var keys = provider.GetRequiredService<IAuthServiceKeysProvider>();

        EnterTenant(provider, acme);
        var atAcme = await keys.GetSigningKeys().ToArrayAsync(TestContext.Current.CancellationToken);
        EnterTenant(provider, globex);
        var atGlobex = await keys.GetSigningKeys().ToArrayAsync(TestContext.Current.CancellationToken);

        Assert.Equal("acme-sign", Assert.Single(atAcme).KeyId);
        Assert.Equal("globex-sign", Assert.Single(atGlobex).KeyId);
    }

    /// <summary>
    /// A tenant naming no key in the custodian has nothing to produce with, and is refused at startup, named.
    /// </summary>
    [Fact]
    public void ATenantNamingNoCustodianKey_IsRefusedAtStartup()
    {
        using var provider = KeysInACustodian([Acme]);

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains("Tenant 'acme': The keys are held by a custodian, and none is named", refusal.Message,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Two tenants naming one custodian key would share it, so a party trusting one's keys verifies the other's
    /// tokens; startup refuses them, naming the key and both tenants.
    /// </summary>
    [Fact]
    public void TwoTenantsNamingOneCustodianKey_AreRefusedAtStartup()
    {
        using var provider = KeysInACustodian(
            [NamingInTheCustodian("acme", "shared-sign"), NamingInTheCustodian("globex", "shared-sign")]);

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains("The custodian key 'shared-sign' is named by the tenants 'acme', 'globex'", refusal.Message,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// A tenant may name one custodian key for both roles, as a server without tenants may: it shares the key with
    /// no other tenant.
    /// </summary>
    [Fact]
    public void ATenantNamingOneCustodianKeyForBothRoles_Starts()
    {
        using var provider = KeysInACustodian(
        [
            new TenantDefinition
            {
                Id = "acme",
                Issuer = AcmeIssuer,
                CustodianKeys = new CustodianHeldKeys { SigningKeyName = "acme-rsa", EncryptionKeyName = "acme-rsa" },
            },
        ]);

        Assert.NotEmpty(provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants);
    }

    /// <summary>
    /// Keys a tenant declares for a placement its server does not use are never read, so startup refuses them,
    /// naming the tenant and the setting, rather than let them read as the keys the tenant produces with.
    /// </summary>
    [Fact]
    public void CustodianKeysOfATenant_WhoseKeysComeFromItsSettings_AreRefusedAtStartup()
    {
        using var provider = KeysFromSettings(new TenantDefinition
        {
            Id = "acme",
            Issuer = AcmeIssuer,
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
            CustodianKeys = new CustodianHeldKeys { SigningKeyName = "acme-sign" },
        });

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains(
            $"Tenant 'acme': {nameof(TenantDefinition)}.{nameof(TenantDefinition.CustodianKeys)} is declared, " +
            "but the keys come from each tenant's settings",
            refusal.Message,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Signing keys a tenant declares while its keys are held by a custodian are never read, so startup refuses them.
    /// </summary>
    [Fact]
    public void SigningKeysOfATenant_WhoseKeysAreHeldByACustodian_AreRefusedAtStartup()
    {
        using var provider = KeysInACustodian(
        [
            new TenantDefinition
            {
                Id = "acme",
                Issuer = AcmeIssuer,
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
                CustodianKeys = new CustodianHeldKeys { SigningKeyName = "acme-sign" },
            },
        ]);

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains(
            $"Tenant 'acme': {nameof(TenantDefinition)}.{nameof(TenantDefinition.SigningKeys)} is declared, " +
            "but the keys are held by a custodian",
            refusal.Message,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// Custodian keys named for the whole server would be ignored under multi-tenancy, so startup refuses them.
    /// </summary>
    [Fact]
    public void CustodianKeysNamedForTheWholeServer_AreRefusedAtStartup()
    {
        using var provider = KeysInACustodian(
            [NamingInTheCustodian("acme", "acme-sign")],
            new CustodianHeldKeys { SigningKeyName = "server-sign" });

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains("The custodian's keys named for the whole server are not used under multi-tenancy",
            refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A container minting its keys, with rings that hold, for each partition, a key whose id is the partition.
    /// </summary>
    private static ServiceProvider MintingKeys(params TenantDefinition[] tenants)
    {
        var rings = new Moq.Mock<IKeyRings>();
        rings.Setup(r => r.For(Moq.It.IsAny<string>())).Returns((string partition) =>
        {
            var ring = new Moq.Mock<IKeyRing>();
            ring.Setup(r => r.Get(PublicKeyUsages.Signature, Moq.It.IsAny<bool>()))
                .Returns([JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature) with { KeyId = partition }]);
            return ring.Object;
        });

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton(Moq.Mock.Of<IKeyCustodian>());
        services.AddSingleton(Moq.Mock.Of<IKeyRingStore>());
        services.AddSingleton(rings.Object);
        services.AddJsonWebTokens();
        services.AddIssuer();
        services.AddAuthServiceJwt();
        services.RequireKeyPlacement().UseKeysInProcess(new MintedKeys { KeyEncryptionKeyName = "kek" });
        services.AddServerStorage().AddMultiTenancy(options =>
        {
            foreach (var tenant in tenants)
                options.Tenants.Add(tenant);
        });
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// A server minting its keys keeps a ring for each tenant, named by the tenant's id.
    /// </summary>
    [Fact]
    public void TheKeyRing_KeepsAPartitionForEachTenant()
    {
        using var provider = MintingKeys(Acme, new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/tenants/globex" });

        Assert.Equal(["acme", "globex"], provider.GetRequiredService<IOptions<KeyRingOptions>>().Value.Partitions);
    }

    /// <summary>
    /// Each tenant publishes and signs with the keys of its own ring.
    /// </summary>
    [Fact]
    public async Task EachTenant_PublishesTheKeysOfItsOwnRing()
    {
        var globex = new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/tenants/globex" };
        using var provider = MintingKeys(Acme, globex);
        var keys = provider.GetRequiredService<IAuthServiceKeysProvider>();

        EnterTenant(provider, Acme);
        var atAcme = await keys.GetSigningKeys().ToArrayAsync(TestContext.Current.CancellationToken);
        EnterTenant(provider, globex);
        var atGlobex = await keys.GetSigningKeys().ToArrayAsync(TestContext.Current.CancellationToken);

        Assert.Equal("acme", Assert.Single(atAcme).KeyId);
        Assert.Equal("globex", Assert.Single(atGlobex).KeyId);
    }

    /// <summary>
    /// Encryption keys a tenant declares while the server mints its keys are never read, so startup refuses them.
    /// </summary>
    [Fact]
    public void EncryptionKeysOfATenant_WhenTheServerMintsTheKeys_AreRefusedAtStartup()
    {
        using var provider = MintingKeys(new TenantDefinition
        {
            Id = "acme",
            Issuer = AcmeIssuer,
            EncryptionKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption)],
        });

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains(
            $"Tenant 'acme': {nameof(TenantDefinition)}.{nameof(TenantDefinition.EncryptionKeys)} is declared, " +
            "but the server mints the keys",
            refusal.Message,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The server keeps each tenant's minted keys under the tenant's id, so an id the key ring cannot name its part
    /// of the store by is refused at startup, naming the tenant.
    /// </summary>
    [Fact]
    public void ATenantIdTheKeyRingCannotNameAPartitionBy_IsRefusedAtStartup()
    {
        using var provider = MintingKeys(new TenantDefinition { Id = "acme.eu", Issuer = AcmeIssuer });

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains("Tenant 'acme.eu': the server mints the keys", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// The server's own mutual-TLS address, or its fixed aliases, name one address for every tenant, which no
    /// request can tell apart, so startup refuses them under multi-tenancy.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void ServerWideMutualTlsAddresses_AreRefusedAtStartup(bool aliases)
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options =>
        {
            if (aliases)
                options.Discovery.MtlsEndpointAliases = new MtlsAliasesOptions { TokenEndpoint = new Uri("https://mtls.example.com/token") };
            else
                options.Discovery.MtlsBaseUri = new Uri("https://mtls.example.com");
        });
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains(
            aliases ? nameof(DiscoveryOptions.MtlsEndpointAliases) : nameof(DiscoveryOptions.MtlsBaseUri),
            refusal.Message,
            StringComparison.Ordinal);
    }

    public static TheoryData<TenantDefinition, string> TenantsTheServersChecksRefuse => new()
    {
        {
            new TenantDefinition
            {
                Id = "acme",
                Issuer = AcmeIssuer,
                DefaultResourceIndicator = new Uri("https://api.acme.example"),
            },
            nameof(OidcOptions.DefaultResourceIndicator)
        },
        {
            new TenantDefinition
            {
                Id = "acme",
                Issuer = AcmeIssuer,
                DefaultSecurityProfile = ClientSecurityProfile.Fapi2,
                Clients = [new ClientInfo("public") { TokenEndpointAuthMethod = ClientAuthenticationMethods.None }],
            },
            "Client 'public'"
        },
        {
            new TenantDefinition
            {
                Id = "acme",
                Issuer = AcmeIssuer,
                Clients = [new ClientInfo("App"), new ClientInfo("app")],
            },
            "2 clients are configured under the id 'App' and 'app'"
        },
        {
            new TenantDefinition
            {
                Id = "acme",
                Issuer = AcmeIssuer,
                Resources = [new ResourceDefinition(new Uri("api", UriKind.Relative))],
            },
            "The resource 'api' must be named by an absolute URI"
        },
    };

    /// <summary>
    /// What a tenant declares passes the checks the server's own settings pass at startup, so a tenant's mistake is
    /// refused there, naming the tenant, rather than surfacing on the first request that meets it.
    /// </summary>
    [Theory]
    [MemberData(nameof(TenantsTheServersChecksRefuse))]
    public void ATenantsSettings_PassTheServersOwnChecks(TenantDefinition tenant, string mistake)
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.TryAddEnumerable([
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, DefaultResourceIndicatorValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, OidcOptionsSecurityProfileValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ClientIdsOptionsValidator>(),
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ResourceDefinitionsValidator>(),
        ]);
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(tenant));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains($"Tenant '{tenant.Id}': ", refusal.Message, StringComparison.Ordinal);
        Assert.Contains(mistake, refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A mistake in the server's own settings is reported by those settings, and does not hide what is wrong with the
    /// tenant list.
    /// </summary>
    [Fact]
    public void InvalidServerSettings_LeaveTheTenantListsOwnRefusalsVisible()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options => options.Issuer = "https://auth.example.com");
        services.AddServerStorage().AddMultiTenancy(options =>
        {
            options.Tenants.Add(Acme);
            options.Tenants.Add(new TenantDefinition { Id = "acme", Issuer = "https://auth.example.com/tenants/other" });
        });
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Equal(typeof(MultiTenancyOptions), refusal.OptionsType);
        Assert.Contains("The tenant id 'acme' is declared more than once.", refusal.Failures);
        Assert.DoesNotContain(refusal.Failures, failure => failure.Contains(nameof(OidcOptions.Issuer), StringComparison.Ordinal));
    }

    /// <summary>
    /// A pairwise client set for the whole server under multi-tenancy gets the refusal of server-wide clients, not a
    /// failure from asking a tenant's settings outside any tenant.
    /// </summary>
    [Fact]
    public void AServerWidePairwiseClient_UnderMultiTenancy_IsRefusedAsServerWide()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options =>
            options.Clients = [new ClientInfo("pairwise") { SubjectType = SubjectTypes.Pairwise }]);
        services.AddIssuer();
        services.AddClientInformation().AddUserInfo();
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains($"{nameof(OidcOptions)}.{nameof(OidcOptions.Clients)} applies to the whole server",
            refusal.Message, StringComparison.Ordinal);
    }

    public static TheoryData<Type, object> HostsOwnRegistries => new()
    {
        { typeof(IClientInfoProvider), Moq.Mock.Of<IClientInfoProvider>() },
        { typeof(IClientInfoManager), Moq.Mock.Of<IClientInfoManager>() },
        { typeof(IScopeManager), Moq.Mock.Of<IScopeManager>() },
        { typeof(IResourceManager), Moq.Mock.Of<IResourceManager>() },
        { typeof(ISubjectTypeConverter), Moq.Mock.Of<ISubjectTypeConverter>() },
        { typeof(IAuthServiceKeysProvider), Moq.Mock.Of<IAuthServiceKeysProvider>() },
    };

    /// <summary>
    /// A registry the host brings itself keeps one set of clients, scopes, resources or pairwise keys for every
    /// tenant, since nothing tells it which tenant a request is for, so startup refuses it, naming the service.
    /// </summary>
    [Theory]
    [MemberData(nameof(HostsOwnRegistries))]
    public void AHostsOwnRegistry_IsRefusedAtStartup(Type service, object registry)
    {
        var services = new ServiceCollection();
        services.AddSingleton(service, registry);
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains($"{service.Name} is the host's own", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A registry the host scopes to a request cannot be resolved at startup, and that failure is reported as the
    /// refusal, naming the service, rather than replacing every refusal of the tenant list with a container error.
    /// </summary>
    [Fact]
    public void AHostsRegistryScopedToARequest_IsRefusedAtStartup()
    {
        var services = new ServiceCollection();
        services.AddScoped(_ => Moq.Mock.Of<IClientInfoProvider>());
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains($"{nameof(IClientInfoProvider)} is the host's own", refusal.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void TheServersOwnRegistries_PassTheStartupCheck(bool reloadableClients)
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddClientInformation().AddUserInfo();
        if (reloadableClients)
            services.AddReloadableClientInformation();
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        Assert.Single(provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants);
    }

    [Fact]
    public void TheServersOwnComposition_PassesTheStartupCheck()
    {
        using var provider = BuildProvider();

        Assert.Single(provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants);
    }

    /// <summary>
    /// A registration made after multi-tenancy replaces the wrapper silently, and every tenant would then read the
    /// others' data - so startup refuses it, naming the service.
    /// </summary>
    [Fact]
    public void AStorageReplacedAfterMultiTenancy_IsRefusedAtStartup()
    {
        var services = new ServiceCollection().AddServerStorage();
        services.AddMultiTenancy(options => options.Tenants.Add(Acme));
        services.Replace(ServiceDescriptor.Singleton<IEntityStorage, DistributedCacheStorage>());
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains($"{nameof(IEntityStorage)} is not kept per tenant", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A budget of an enabled endpoint is checked as well, named with its key.
    /// </summary>
    [Fact]
    public void AnEndpointBudgetReplacedAfterMultiTenancy_IsRefusedAtStartup()
    {
        var services = new ServiceCollection().AddServerStorage().AddIntrospection();
        services.AddMultiTenancy(options => options.Tenants.Add(Acme));
        services.AddKeyedSingleton(
            CallerRateLimiters.Introspection,
            PartitionedRateLimiter.Create<(string ClientId, string? Source), string>(
                resource => RateLimitPartition.GetNoLimiter(resource.ClientId)));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains(CallerRateLimiters.Introspection, refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void TheStorageTheServerResolves_IsKeptPerTenant()
    {
        using var provider = BuildProvider();

        Assert.IsType<TenantEntityStorage>(provider.GetRequiredService<IEntityStorage>());
    }

    /// <summary>
    /// A request that reached the server without a tenant has no issuer of its own; answering with the host
    /// would mint tokens every tenant on it accepts.
    /// </summary>
    [Fact]
    public void WithoutATenant_TheIssuerIsRefused()
    {
        using var provider = BuildProvider();
        EnterTenant(provider, null);

        var issuerProvider = provider.GetRequiredService<IIssuerProvider>();

        var refusal = Assert.Throws<InvalidOperationException>(() => issuerProvider.GetIssuer());
        Assert.Contains("not resolved to a tenant", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void AConfiguredIssuer_IsRefusedAtStartup()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options => options.Issuer = "https://auth.example.com");
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains(nameof(OidcOptions.Issuer), refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A setting a tenant declares, set for the whole server, is refused at startup. Which settings those are is
    /// held by the core's own tests of the refusal; this one holds that multi-tenancy puts the refusal in force.
    /// </summary>
    [Fact]
    public void ServerWideClients_AreRefusedAtStartup()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>().Configure(options => options.Clients = [new ClientInfo("client")]);
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains($"{nameof(OidcOptions)}.{nameof(OidcOptions.Clients)} ", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void UnderATenant_TheClientsAreTheOnesItDeclares()
    {
        var acme = new TenantDefinition { Id = "acme", Issuer = AcmeIssuer, Clients = [new ClientInfo("client")] };
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(acme));
        using var provider = services.BuildServiceProvider();
        EnterTenant(provider, acme);

        Assert.Same(acme.Clients, provider.GetRequiredService<IIssuerSettings>().Clients);
    }

    [Fact]
    public void EachTenant_KeepsAValueOfItsOwn_AndNoTenantGetsNone()
    {
        using var provider = BuildProvider();
        var local = provider.GetRequiredService<IIssuerLocal<object>>();
        var globex = new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/tenants/globex" };

        EnterTenant(provider, Acme);
        var acmeValue = local.GetOrCreate(null, () => new object());
        Assert.Same(acmeValue, local.GetOrCreate(null, () => new object()));

        EnterTenant(provider, globex);
        Assert.NotSame(acmeValue, local.GetOrCreate(null, () => new object()));

        EnterTenant(provider, null);
        var refusal = Assert.Throws<InvalidOperationException>(() => local.GetOrCreate(null, () => new object()));
        Assert.Contains("outside any tenant", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void WithoutATenant_TheSettingsAreRefused()
    {
        using var provider = BuildProvider();
        EnterTenant(provider, null);

        var settings = provider.GetRequiredService<IIssuerSettings>();

        var refusal = Assert.Throws<InvalidOperationException>(() => settings.Clients);
        Assert.Contains("outside any tenant", refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheCatalog_FindsATenantByIdExactly_AndByItsIssuersAddress()
    {
        var services = new ServiceCollection();
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        await using var provider = services.BuildServiceProvider();
        var catalog = provider.GetRequiredService<ITenantCatalog>();
        var cancellationToken = TestContext.Current.CancellationToken;

        Assert.Equal("acme", (await catalog.FindByIdAsync("acme", cancellationToken))?.Id);
        Assert.Null(await catalog.FindByIdAsync("ACME", cancellationToken));
        Assert.Equal("acme",
            (await catalog.FindByAddressAsync("AUTH.example.com.", "/tenants/acme/connect/token", cancellationToken))?.Id);
        Assert.Null(await catalog.FindByAddressAsync("auth.example.com", "/connect/token", cancellationToken));
    }

    /// <summary>
    /// Resolution missing from the pipeline looks exactly like a request naming no tenant, so the refusal is
    /// logged only in the first case: every OpenID endpoint answers 404 there, and the log names the missing call.
    /// </summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task ARefusalWithoutResolution_IsLogged_AndOneAfterIt_IsNot(bool resolutionRan, bool logged)
    {
        var logs = new EventRecorder();
        var services = new ServiceCollection();
        services.AddSingleton<ILoggerFactory>(logs);
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        await using var provider = services.BuildServiceProvider();

        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Host = new HostString("other.example.com");
        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = context;

        var unmet = false;
        RequestDelegate endpoint = httpContext =>
        {
            unmet = TenantRequirement.IsUnmet(httpContext);
            return Task.CompletedTask;
        };

        if (resolutionRan)
            await new TenantResolutionMiddleware(endpoint, provider.GetRequiredService<ITenantCatalog>()).InvokeAsync(context);
        else
            await endpoint(context);

        Assert.True(unmet);
        Assert.Equal(logged, logs.EventIds.Contains(LogEvents.MultiTenancy.ResolutionNotInPipeline));
    }

    private sealed class EventRecorder : ILoggerFactory, ILogger
    {
        public List<int> EventIds { get; } = [];

        public ILogger CreateLogger(string categoryName) => this;

        public void AddProvider(ILoggerProvider provider)
        {
        }

        public void Dispose()
        {
        }

        public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

        public bool IsEnabled(LogLevel logLevel) => true;

        public void Log<TState>(
            LogLevel logLevel, EventId eventId, TState state, Exception? exception,
            Func<TState, Exception?, string> formatter)
            => EventIds.Add(eventId.Id);
    }

    /// <summary>
    /// A request that names no tenant is refused at the OpenID endpoints only where multi-tenancy is on; a
    /// deployment that never enabled it serves as before.
    /// </summary>
    [Fact]
    public void TheTenantRequirement_HoldsOnlyUnderMultiTenancy()
    {
        using var plain = new ServiceCollection().BuildServiceProvider();
        using var multiTenant = BuildProvider();

        Assert.False(TenantRequirement.IsUnmet(new DefaultHttpContext { RequestServices = plain }));

        EnterTenant(multiTenant, null);
        Assert.True(TenantRequirement.IsUnmet(new DefaultHttpContext { RequestServices = multiTenant }));

        EnterTenant(multiTenant, Acme);
        Assert.False(TenantRequirement.IsUnmet(new DefaultHttpContext { RequestServices = multiTenant }));
    }

    /// <summary>
    /// The tenant is asked of the accessor everywhere, so a host that resolves tenants its own way - setting
    /// nothing on the request - is answered the same by the endpoints as by the issuer.
    /// </summary>
    [Fact]
    public void AHostsOwnTenantAccessor_IsWhatEveryQuestionAsks()
    {
        var services = new ServiceCollection();
        services.AddSingleton<ITenantAccessor>(new FixedTenantAccessor(Acme));
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var context = new DefaultHttpContext { RequestServices = provider };

        Assert.False(TenantRequirement.IsUnmet(context));
        Assert.Same(Acme, TenantRequirement.CurrentTenant(context)?.Tenant);
        Assert.Equal(AcmeIssuer, provider.GetRequiredService<IIssuerProvider>().GetIssuer());
    }

    private sealed class FixedTenantAccessor(TenantDefinition tenant) : ITenantAccessor
    {
        public TenantContext Current { get; } = new() { Tenant = tenant };
    }
}
