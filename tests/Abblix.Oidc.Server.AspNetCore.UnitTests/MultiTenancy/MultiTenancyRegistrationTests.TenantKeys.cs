// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.Tokens.Validation;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

public partial class MultiTenancyRegistrationTests
{
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
}
