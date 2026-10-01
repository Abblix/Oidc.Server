// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections;
using System.Collections.Generic;
using System.Security.Cryptography;
using System.Threading;
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
using Abblix.Oidc.Server.Features.Tokens.Validation;
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
    /// A rule the host adds to the server's settings the usual way, bound to the default name, judges each tenant's
    /// settings too, and its refusal names the tenant.
    /// </summary>
    [Fact]
    public void AHostsOwnRule_JudgesEachTenantsSettings()
    {
        const string HostRule = "The host signs with one key at a time.";

        // The same tenant starts without the rule, so the refusal below is the rule's
        using var withoutTheRule = TwoSigningKeys(hostRule: false);
        Assert.NotEmpty(withoutTheRule.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants);

        using var withTheRule = TwoSigningKeys(hostRule: true);
        var refusal = Assert.Throws<OptionsValidationException>(
            () => withTheRule.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains($"Tenant 'acme': {HostRule}", refusal.Message, StringComparison.Ordinal);

        ServiceProvider TwoSigningKeys(bool hostRule)
        {
            var services = new ServiceCollection();
            var options = services.AddOptions<OidcOptions>();
            if (hostRule)
                options.Validate(settings => settings.SigningKeys.Count <= 1, HostRule);

            services.AddIssuer();
            services.AddAuthServiceJwt();
            services.AddServerStorage().AddMultiTenancy(tenants => tenants.Tenants.Add(new TenantDefinition
            {
                Id = "acme",
                Issuer = AcmeIssuer,
                SigningKeys =
                [
                    JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature),
                    JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature),
                ],
            }));
            return services.BuildServiceProvider();
        }
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

        // Refused by the check the server reads its own tokens with. Read with it at acme too, the token would have
        // it count acme's issuer against the license, which this suite does not lift.
        var atGlobex = await provider.GetRequiredService<IAuthServiceJwtValidator>().ValidateAsync(encrypted);
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
    private static ServiceProvider MintingKeys(params TenantDefinition[] tenants) => MintingKeys(_ => { }, tenants);

    private static ServiceProvider MintingKeys(Action<IServiceCollection> host, params TenantDefinition[] tenants)
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
        host(services);
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
        var globex = new TenantDefinition
        {
            Id = "globex",
            Issuer = "https://auth.example.com/tenants/globex",
            Generation = "2",
        };
        using var provider = MintingKeys(Acme, globex);
        var keys = provider.GetRequiredService<IAuthServiceKeysProvider>();

        EnterTenant(provider, Acme);
        var atAcme = await keys.GetSigningKeys().ToArrayAsync(TestContext.Current.CancellationToken);
        EnterTenant(provider, globex);
        var atGlobex = await keys.GetSigningKeys().ToArrayAsync(TestContext.Current.CancellationToken);

        Assert.Equal("acme", Assert.Single(atAcme).KeyId);
        Assert.Equal("globex~2", Assert.Single(atGlobex).KeyId);
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
    /// The server keeps each tenant's minted keys under its id and generation, so an id the key ring cannot name its
    /// part of the store by, or one holding the separator of a generation, is refused at startup, naming the tenant.
    /// </summary>
    [Theory]
    [InlineData("acme.eu")]
    [InlineData("acme~eu")] // the separator of a generation, which would let this id name another tenant's partition
    public void ATenantIdTheKeyRingCannotNameAPartitionBy_IsRefusedAtStartup(string id)
    {
        using var provider = MintingKeys(new TenantDefinition { Id = id, Issuer = AcmeIssuer });

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains($"Tenant '{id}': the server mints the keys", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A store of the host's own beside tenants the settings declare starts, as long as each tenant's keys come
    /// from its settings: whether that store serves them too is the host's composition.
    /// </summary>
    [Fact]
    public void AStoreOfTheHostsOwn_BesideTenantsInTheSettings_Starts()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddAuthServiceJwt();
        services.AddSingleton(Moq.Mock.Of<ITenantStore>());
        services.AddServerStorage().AddMultiTenancy(options => options.Tenants.Add(new TenantDefinition
        {
            Id = "acme",
            Issuer = AcmeIssuer,
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        }));
        using var provider = services.BuildServiceProvider();

        Assert.NotEmpty(provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants);
    }

    /// <summary>
    /// Keys the server mints are kept for the tenants the settings declare, so a store of the host's own is
    /// refused with them at startup, rather than leave each tenant it holds without a key to sign with.
    /// </summary>
    [Fact]
    public void MintedKeys_BesideAStoreOfTheHostsOwn_AreRefusedAtStartup()
    {
        using var provider = MintingKeys(services => services.AddSingleton(Moq.Mock.Of<ITenantStore>()));

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains("would have none to sign with", refusal.Message, StringComparison.Ordinal);
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

    /// <summary>
    /// A tenant whose definition changes while the server runs - read again from a store of tenants - is served
    /// the clients the new definition declares: one it dropped no longer authenticates, one it added does.
    /// </summary>
    [Fact]
    public async Task ATenantsChangedDefinition_ServesTheClientsItNowDeclares()
    {
        TenantDefinition Acme(string clientId)
            => new() { Id = "acme", Issuer = AcmeIssuer, Clients = [new ClientInfo(clientId)] };

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddClientInformation();
        services.AddServerStorage().AddMultiTenancy(_ => { });
        using var provider = services.BuildServiceProvider();
        var clients = provider.GetRequiredService<IClientInfoProvider>();

        EnterTenant(provider, Acme("before"));
        Assert.NotNull(await clients.TryFindClientAsync("before"));

        EnterTenant(provider, Acme("after"));
        Assert.Null(await clients.TryFindClientAsync("before"));
        Assert.NotNull(await clients.TryFindClientAsync("after"));
    }

    /// <summary>
    /// A store of tenants whose listing changes between readings, as one the host edits while the server runs.
    /// </summary>
    private sealed class ChangingTenantStore : ITenantStore
    {
        public IReadOnlyCollection<StoredTenant> Tenants { get; set; } = [];

        public Task<IReadOnlyCollection<StoredTenant>> ListAsync(CancellationToken cancellationToken)
            => Task.FromResult(Tenants);
    }

    /// <summary>
    /// A catalog of the host's own: it passes on what the server's catalog serves until the host hands out a
    /// definition of its own.
    /// </summary>
    private sealed class HostCatalog(StoreTenantCatalog inner) : ITenantCatalog
    {
        public TenantDefinition? Own { get; set; }

        public async ValueTask<TenantDefinition?> FindByIdAsync(string tenantId, CancellationToken cancellationToken)
            => Own ?? await inner.FindByIdAsync(tenantId, cancellationToken);

        public async ValueTask<TenantDefinition?> FindByAddressAsync(
            string host,
            string path,
            CancellationToken cancellationToken)
            => Own ?? await inner.FindByAddressAsync(host, path, cancellationToken);
    }

    private static ServiceProvider ServingFrom(ChangingTenantStore store, bool hostCatalog = false)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        services.AddClientInformation();
        services.AddSingleton<ITenantStore>(store);
        if (hostCatalog)
        {
            services.AddSingleton<HostCatalog>();
            services.AddSingleton<ITenantCatalog>(serviceProvider => serviceProvider.GetRequiredService<HostCatalog>());
        }

        services.AddServerStorage().AddMultiTenancy(_ => { });
        return services.BuildServiceProvider();
    }

    /// <summary>
    /// The definition the server serves once the store holds <paramref name="tenant"/> under
    /// <paramref name="version"/> and has been read again.
    /// </summary>
    private static async Task<TenantDefinition> Served(
        IServiceProvider provider,
        ChangingTenantStore store,
        TenantDefinition tenant,
        string version)
    {
        store.Tenants = [new StoredTenant(tenant, version)];
        var catalog = provider.GetRequiredService<StoreTenantCatalog>();
        await catalog.RefreshAsync(CancellationToken.None);
        var served = await catalog.FindByIdAsync(tenant.Id, CancellationToken.None);
        Assert.NotNull(served);
        return served;
    }

    private static TenantDefinition AcmeWith(params string[] clientIds) => new()
    {
        Id = "acme",
        Issuer = AcmeIssuer,
        Clients = [..clientIds.Select(id => new ClientInfo(id) { TokenEndpointAuthMethod = ClientAuthenticationMethods.None })],
    };

    /// <summary>
    /// A request begun before a tenant's definition changed holds the former one to its end; reaching the client
    /// store then, it does not bring the former definition back and drop a client registered under an id the new
    /// definition freed.
    /// </summary>
    [Fact]
    public async Task ARequestHoldingAFormerDefinition_DoesNotDropARegistrationMadeSince()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith("freed"), "1");
        EnterTenant(provider, former);
        Assert.NotNull(await clients.TryFindClientAsync("freed"));

        var current = await Served(provider, store, AcmeWith(), "2");
        EnterTenant(provider, current);
        Assert.True(await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("freed"), "token-id")));

        EnterTenant(provider, former);
        await clients.TryFindClientAsync("freed");

        EnterTenant(provider, current);
        Assert.NotNull(await manager.TryFindRegisteredClientAsync("freed"));
    }

    /// <summary>
    /// A request holding a definition the store replaced twice since does not leave the tenant served the
    /// definition between the two.
    /// </summary>
    [Fact]
    public async Task ARequestHoldingADefinitionBetweenTwoChanges_DoesNotHoldTheTenantThere()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();

        EnterTenant(provider, await Served(provider, store, AcmeWith("first"), "1"));
        Assert.NotNull(await clients.TryFindClientAsync("first"));
        var between = await Served(provider, store, AcmeWith("between"), "2");
        var last = await Served(provider, store, AcmeWith("last"), "3");
        EnterTenant(provider, last);
        Assert.NotNull(await clients.TryFindClientAsync("last"));

        EnterTenant(provider, between);
        Assert.Null(await clients.TryFindClientAsync("between"));

        EnterTenant(provider, last);
        Assert.NotNull(await clients.TryFindClientAsync("last"));
        Assert.Null(await clients.TryFindClientAsync("between"));
    }

    /// <summary>
    /// A tenant whose clients are all removed stops serving them, although every definition declaring no clients
    /// hands out one and the same empty list.
    /// </summary>
    [Fact]
    public async Task ATenantLeftWithNoClients_StopsServingTheOnesItHad()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();

        EnterTenant(provider, await Served(provider, store, new TenantDefinition { Id = "acme", Issuer = AcmeIssuer }, "1"));
        Assert.Null(await clients.TryFindClientAsync("removed"));
        EnterTenant(provider, await Served(provider, store, AcmeWith("removed"), "2"));
        Assert.NotNull(await clients.TryFindClientAsync("removed"));

        EnterTenant(provider, await Served(provider, store, new TenantDefinition { Id = "acme", Issuer = AcmeIssuer }, "3"));
        Assert.Null(await clients.TryFindClientAsync("removed"));
    }

    /// <summary>
    /// A store handing back, as a new version, a definition object it handed out before - a rollback to a kept
    /// one - has that definition served again.
    /// </summary>
    [Fact]
    public async Task ADefinitionHandedBackAgain_IsServedAgain()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var kept = AcmeWith("kept");

        EnterTenant(provider, await Served(provider, store, kept, "1"));
        Assert.NotNull(await clients.TryFindClientAsync("kept"));
        EnterTenant(provider, await Served(provider, store, AcmeWith("replacing"), "2"));
        Assert.NotNull(await clients.TryFindClientAsync("replacing"));

        EnterTenant(provider, await Served(provider, store, kept, "3"));
        Assert.NotNull(await clients.TryFindClientAsync("kept"));
    }

    /// <summary>
    /// Clients a definition declares, whose reading, once armed, stops until the test lets it go on: it holds the
    /// store mid-way through building them.
    /// </summary>
    private sealed class HeldClients(params ClientInfo[] clients) : IEnumerable<ClientInfo>
    {
        public bool Armed { get; set; }
        public SemaphoreSlim Reached { get; } = new(0);
        public SemaphoreSlim Released { get; } = new(0);

        public IEnumerator<ClientInfo> GetEnumerator()
        {
            if (Armed)
            {
                Armed = false;
                Reached.Release();
                Released.Wait();
            }

            return ((IEnumerable<ClientInfo>)clients).GetEnumerator();
        }

        IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
    }

    /// <summary>
    /// A registration under an id the served definition configures, decided by a request holding the former one
    /// while the clients of the served one are being built, is answered as not made rather than kept and then
    /// dropped by that build.
    /// </summary>
    [Fact]
    public async Task ARegistrationDuringTheBuildOfTheClients_IsAnsweredByThem()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith(), "1");
        EnterTenant(provider, former);
        Assert.Null(await clients.TryFindClientAsync("taken"));

        var held = new HeldClients(new ClientInfo("taken") { TokenEndpointAuthMethod = ClientAuthenticationMethods.None });
        var current = await Served(provider, store, new TenantDefinition { Id = "acme", Issuer = AcmeIssuer, Clients = held }, "2");
        held.Armed = true;
        var building = Task.Run(async () =>
        {
            EnterTenant(provider, current);
            return await clients.TryFindClientAsync("taken");
        });
        await held.Reached.WaitAsync(TestContext.Current.CancellationToken);

        var registering = Task.Run(async () =>
        {
            EnterTenant(provider, former);
            return await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("taken"), "token-id"));
        });
        await Task.WhenAny(registering, Task.Delay(TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken));
        held.Released.Release();

        Assert.NotNull(await building);
        Assert.False(await registering);
    }

    /// <summary>
    /// A store handing the former definition back in a reading the checks refuse leaves it unserved, so a request
    /// still holding it does not drop a client registered since under the id it configures.
    /// </summary>
    [Fact]
    public async Task ARefusedRollback_DoesNotLetARequestHoldingTheFormerDefinitionDropARegistration()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var catalog = provider.GetRequiredService<StoreTenantCatalog>();
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith("freed"), "1");
        EnterTenant(provider, former);
        Assert.NotNull(await clients.TryFindClientAsync("freed"));
        var current = await Served(provider, store, AcmeWith(), "2");
        EnterTenant(provider, current);
        Assert.True(await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("freed"), "token-id")));

        // Globex claims acme's issuer, so the checks refuse both
        store.Tenants =
        [
            new StoredTenant(former, "3"),
            new StoredTenant(new TenantDefinition { Id = "globex", Issuer = AcmeIssuer }, "1"),
        ];
        await catalog.RefreshAsync(CancellationToken.None);
        Assert.Null(await catalog.FindByIdAsync("acme", CancellationToken.None));

        EnterTenant(provider, former);
        await clients.TryFindClientAsync("freed");

        EnterTenant(provider, current);
        Assert.NotNull(await manager.TryFindRegisteredClientAsync("freed"));
    }

    /// <summary>
    /// A tenant the store no longer holds still answers a request holding its definition, without building from it
    /// again and dropping a client registered under the id it configures.
    /// </summary>
    [Fact]
    public async Task ATenantTheStoreDropped_DoesNotLetARequestHoldingItDropARegistration()
    {
        var store = new ChangingTenantStore();
        using var provider = ServingFrom(store);
        var clients = provider.GetRequiredService<IClientInfoProvider>();
        var manager = provider.GetRequiredService<IClientInfoManager>();

        var former = await Served(provider, store, AcmeWith("freed"), "1");
        EnterTenant(provider, former);
        Assert.NotNull(await clients.TryFindClientAsync("freed"));
        var current = await Served(provider, store, AcmeWith(), "2");
        EnterTenant(provider, current);
        Assert.True(await manager.TryAddClientAsync(new RegisteredClient(new ClientInfo("freed"), "token-id")));

        store.Tenants = [];
        await provider.GetRequiredService<StoreTenantCatalog>().RefreshAsync(CancellationToken.None);

        EnterTenant(provider, former);
        await clients.TryFindClientAsync("freed");

        EnterTenant(provider, current);
        Assert.NotNull(await manager.TryFindRegisteredClientAsync("freed"));
    }

    /// <summary>
    /// Under a catalog of the host's own, a tenant the host hands a definition of its own is served the clients it
    /// declares, though the server's catalog, still reading the store, served another definition before.
    /// </summary>
    [Fact]
    public async Task UnderAHostCatalog_ADefinitionOfItsOwn_IsServedItsClients()
    {
        var store = new ChangingTenantStore { Tenants = [new StoredTenant(AcmeWith("stored"), "1")] };
        using var provider = ServingFrom(store, hostCatalog: true);
        await provider.GetRequiredService<StoreTenantCatalog>().RefreshAsync(CancellationToken.None);
        var catalog = provider.GetRequiredService<HostCatalog>();
        var clients = provider.GetRequiredService<IClientInfoProvider>();

        EnterTenant(provider, await catalog.FindByIdAsync("acme", CancellationToken.None));
        Assert.NotNull(await clients.TryFindClientAsync("stored"));

        catalog.Own = AcmeWith("own");
        EnterTenant(provider, await catalog.FindByIdAsync("acme", CancellationToken.None));
        Assert.NotNull(await clients.TryFindClientAsync("own"));
    }

    /// <summary>
    /// One definition object served by the catalogs of two servers in one process, each reading its store in its
    /// own order, leaves each server free to move on to the next definition it serves.
    /// </summary>
    [Fact]
    public async Task ADefinitionServedByTwoServers_LeavesEachFreeToMoveOn()
    {
        var shared = AcmeWith("shared");
        var firstStore = new ChangingTenantStore();
        var secondStore = new ChangingTenantStore();
        using var first = ServingFrom(firstStore);
        using var second = ServingFrom(secondStore);
        var clients = second.GetRequiredService<IClientInfoProvider>();

        var sharedInSecond = await Served(second, secondStore, shared, "1");
        foreach (var version in new[] { "1", "2", "3" })
            await Served(first, firstStore, AcmeWith(version), version);
        await Served(first, firstStore, shared, "4");
        EnterTenant(second, sharedInSecond);
        Assert.NotNull(await clients.TryFindClientAsync("shared"));

        EnterTenant(second, await Served(second, secondStore, AcmeWith("later"), "2"));
        Assert.NotNull(await clients.TryFindClientAsync("later"));
    }

    /// <summary>
    /// The default client store follows each tenant's definition under multi-tenancy, whichever of the two calls
    /// comes first, and reads a server's clients once without it, as before; the store finding clients is the one
    /// keeping them.
    /// </summary>
    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    public void TheDefaultClientStore_FollowsTenants_OnlyUnderMultiTenancy(bool multiTenancy, bool clientsFirst)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddOptions<OidcOptions>();
        services.AddIssuer();
        if (clientsFirst)
            services.AddClientInformation();
        if (multiTenancy)
            services.AddServerStorage().AddMultiTenancy(_ => { });
        if (!clientsFirst)
            services.AddClientInformation();
        using var provider = services.BuildServiceProvider();

        var finding = provider.GetRequiredService<IClientInfoProvider>();
        Assert.Same(finding, provider.GetRequiredService<IClientInfoManager>());
        Assert.Equal(
            multiTenancy ? "ReloadableClientInfoStorage" : "ClientInfoStorage",
            finding.GetType().Name);
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

    /// <summary>
    /// A tenant created again under the id of one removed builds its own values, rather than taking over what was
    /// built for the removed one.
    /// </summary>
    [Fact]
    public void ATenantCreatedAgainUnderAnId_BuildsValuesOfItsOwn()
    {
        using var provider = BuildProvider();
        var local = provider.GetRequiredService<IIssuerLocal<object>>();
        TenantDefinition Acme(string generation)
            => new() { Id = "acme", Issuer = AcmeIssuer, Generation = generation };

        EnterTenant(provider, Acme("1"));
        var former = local.GetOrCreate(null, () => new object());

        EnterTenant(provider, Acme("2"));
        Assert.NotSame(former, local.GetOrCreate(null, () => new object()));
    }

    /// <summary>
    /// The keys the server mints for a tenant are kept in a partition named by its id and generation, so a tenant
    /// created again under the id of one removed mints keys of its own; a tenant the settings declare keeps the
    /// partition named by its id alone.
    /// </summary>
    [Fact]
    public void TheKeyRing_KeepsAPartitionForEachCreationOfATenant()
    {
        using var provider = MintingKeys(
            Acme,
            new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/tenants/globex", Generation = "2" });

        Assert.Equal(["acme", "globex~2"], provider.GetRequiredService<IOptions<KeyRingOptions>>().Value.Partitions);
    }

    /// <summary>
    /// A generation names the tenant's data and keys, so one holding what a store may refuse is refused at startup.
    /// </summary>
    [Fact]
    public void AGenerationHoldingWhatAStoreMayRefuse_IsRefusedAtStartup()
    {
        using var provider = KeysFromSettings(new TenantDefinition
        {
            Id = "acme",
            Issuer = AcmeIssuer,
            Generation = "a.b",
            SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)],
        });

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value);
        Assert.Contains("The generation 'a.b' of tenant 'acme'", refusal.Message, StringComparison.Ordinal);
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
