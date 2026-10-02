// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

public partial class MultiTenancyRegistrationTests
{
    private const string KeyEncryptionKeyName = "kek";

    /// <summary>
    /// A key ring store keeping its entries in memory, shared by every ring of one container.
    /// </summary>
    private sealed class MemoryKeyRingStore : IKeyRingStore
    {
        private readonly Lock _entriesLock = new();
        private readonly List<StoredKey> _entries = [];

        public Task<IReadOnlyList<StoredKey>> LoadAsync(CancellationToken cancellationToken)
        {
            lock (_entriesLock)
                return Task.FromResult<IReadOnlyList<StoredKey>>([.._entries]);
        }

        public Task<bool> TryAddAsync(StoredKey key, CancellationToken cancellationToken)
        {
            lock (_entriesLock)
            {
                if (_entries.Exists(entry => entry.Id == key.Id))
                    return Task.FromResult(false);

                _entries.Add(key);
                return Task.FromResult(true);
            }
        }

        public Task RemoveAsync(string id, CancellationToken cancellationToken)
        {
            lock (_entriesLock)
                _entries.RemoveAll(entry => entry.Id == id);

            return Task.CompletedTask;
        }
    }

    /// <summary>
    /// A container minting its keys for real: each ring seals what it mints to a key-encryption key a stub custodian
    /// holds, and keeps it in a store in memory.
    /// </summary>
    private static ServiceProvider MintingRealKeys(ChangingTenantStore store, params JsonWebKey[] adoptedKeys)
    {
        var keyEncryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption) with { KeyId = "kek-1" };
        var custodian = new Moq.Mock<IKeyCustodian>();
        custodian
            .Setup(c => c.GetKeyVersionsAsync(KeyEncryptionKeyName, Moq.It.IsAny<CancellationToken>()))
            .Returns(new[] { new KeyVersion(keyEncryptionKey.Sanitize(false), DateTimeOffset.UnixEpoch) }
                .ToAsyncEnumerable());
        custodian
            .Setup(c => c.UnwrapKeyAsync(
                keyEncryptionKey.KeyId!, Moq.It.IsAny<string>(), Moq.It.IsAny<JsonWebTokenHeader>(),
                Moq.It.IsAny<byte[]>(), Moq.It.IsAny<CancellationToken>()))
            .Returns((string _, string algorithm, JsonWebTokenHeader _, byte[] encryptedKey, CancellationToken _) =>
                Task.FromResult<byte[]?>(Unwrap(keyEncryptionKey, algorithm, encryptedKey)));

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddSingleton(TimeProvider.System);
        services.AddSingleton(custodian.Object);
        services.AddSingleton<IKeyRingStore>(new MemoryKeyRingStore());
        services.AddSingleton<ITenantStore>(store);
        services.AddJsonWebTokens();
        services.AddIssuer();
        services.AddAuthServiceJwt();
        services.RequireKeyPlacement()
            .UseKeysInProcess(new MintedKeys
            {
                KeyEncryptionKeyName = KeyEncryptionKeyName,
                AdoptedKeys = adoptedKeys,
            });
        services.AddServerStorage().AddMultiTenancy(_ => { });
        return services.BuildServiceProvider();
    }

    private static byte[] Unwrap(RsaJsonWebKey keyEncryptionKey, string algorithm, byte[] encryptedKey)
    {
        using var rsa = RSA.Create();
        rsa.ImportParameters(keyEncryptionKey.ToRsaParameters());
        var padding = algorithm == EncryptionAlgorithms.KeyManagement.RsaOaep256
            ? RSAEncryptionPadding.OaepSHA256
            : RSAEncryptionPadding.OaepSHA1;
        return rsa.Decrypt(encryptedKey, padding);
    }

    /// <summary>
    /// A tenant the host adds to its own store while the server runs signs with a key of its own once the store is
    /// read again, with no restart: the server mints its first key before it starts serving the tenant.
    /// </summary>
    [Fact]
    public async Task ATenantAddedToTheHostsStore_SignsWithAKeyOfItsOwn_OnceTheStoreIsReadAgain()
    {
        var store = new ChangingTenantStore();
        using var provider = MintingRealKeys(store);
        Assert.Empty(provider.GetRequiredService<IOptions<MultiTenancyOptions>>().Value.Tenants);

        var globex = new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/tenants/globex" };
        store.Tenants = [new StoredTenant(Acme, "1"), new StoredTenant(globex, "1")];
        var catalog = provider.GetRequiredService<StoreTenantCatalog>();
        await catalog.RefreshAsync(TestContext.Current.CancellationToken);

        var keys = provider.GetRequiredService<IAuthServiceKeysProvider>();
        EnterTenant(provider, await catalog.FindByIdAsync("acme", TestContext.Current.CancellationToken));
        var atAcme = await keys.GetSigningKeys().ToArrayAsync(TestContext.Current.CancellationToken);
        EnterTenant(provider, await catalog.FindByIdAsync("globex", TestContext.Current.CancellationToken));
        var atGlobex = await keys.GetSigningKeys().ToArrayAsync(TestContext.Current.CancellationToken);

        Assert.NotEqual(Assert.Single(atAcme).KeyId, Assert.Single(atGlobex).KeyId);
    }

    /// <summary>
    /// A tenant the host removes from its store is no longer rotated once the store is read again, while a request
    /// that began before still finds its keys.
    /// </summary>
    [Fact]
    public async Task ATenantRemovedFromTheHostsStore_IsNoLongerKept_OnceTheStoreIsReadAgain()
    {
        var store = new ChangingTenantStore();
        using var provider = MintingRealKeys(store);
        var globex = new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/tenants/globex" };
        var catalog = provider.GetRequiredService<StoreTenantCatalog>();
        var partitions = provider.GetRequiredService<IKeyRingPartitions>();

        store.Tenants = [new StoredTenant(Acme, "1"), new StoredTenant(globex, "1")];
        await catalog.RefreshAsync(TestContext.Current.CancellationToken);
        Assert.Equal(["acme", "globex"], partitions.Kept.Order());

        store.Tenants = [new StoredTenant(Acme, "1")];
        await catalog.RefreshAsync(TestContext.Current.CancellationToken);
        Assert.Equal(["acme"], partitions.Kept);

        EnterTenant(provider, globex);
        var stillHeld = await provider.GetRequiredService<IAuthServiceKeysProvider>().GetSigningKeys()
            .ToArrayAsync(TestContext.Current.CancellationToken);
        Assert.Single(stillHeld);
    }

    /// <summary>
    /// Keys adopted into the ring would be seeded into each tenant's part of it, so a server serving tenants refuses
    /// to start with them, its store empty or not.
    /// </summary>
    [Fact]
    public async Task AdoptedKeys_UnderMultiTenancy_RefuseTheStart()
    {
        using var provider = MintingRealKeys(
            new ChangingTenantStore(),
            JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature));

        await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            foreach (var service in provider.GetServices<IHostedService>())
                await service.StartAsync(TestContext.Current.CancellationToken);
        });
    }
}
