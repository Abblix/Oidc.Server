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

using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.Vault.UnitTests;

/// <summary>
/// Covers what only a built provider can answer: how many of each service a host actually ends up with, and whose
/// registration wins. Both are invisible in the registration code and silent at runtime when wrong.
/// </summary>
public class DiProbeTests
{
    private static IServiceCollection Configure()
    {
        var services = new ServiceCollection();
        services.AddJsonWebTokens();
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);
        return services;
    }

    [Fact]
    public void CustodianIsSharedAcrossConsumers()
    {
        var services = Configure();
        services.AddVaultCustodian(options => options.Address = "https://vault.test:8200")
            .HoldKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "k" });

        using var provider = services.BuildServiceProvider();

        // One custodian, however many services consume it. A per-consumer custodian would work in every test and
        // still be wrong in production: each copy carries its own credential and its own caches.
        Assert.Same(provider.GetRequiredService<IKeyCustodian>(), provider.GetRequiredService<IKeyCustodian>());
    }

    [Fact]
    public void CustodianAndKeyRingShareOneTransport()
    {
        var services = Configure();
        services.AddVaultCustodian(options => options.Address = "https://vault.test:8200")
            .MintKeysInProcess(new MintedKeys { KeyEncryptionKeyName = "oidc-kek" })
            .PersistRingToVaultKeyValue();

        using var provider = services.BuildServiceProvider();

        // Both engines live on one Vault behind one token, so they talk through one client and one connection
        // pool. Wiring each engine its own would work and simply cost twice the pools, which nothing would report.
        Assert.Same(
            provider.GetRequiredService<IApiClient>(),
            provider.GetRequiredService<IApiClient>());

        Assert.NotNull(provider.GetRequiredService<IKeyCustodian>());
        Assert.NotNull(provider.GetRequiredService<IKeyRingStore>());
    }

    private sealed class HostCustodian : IKeyCustodian
    {
        public Task<byte[]> SignAsync(string keyId, string algorithm, byte[] data, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<byte[]?> UnwrapKeyAsync(string keyId, string algorithm, JsonWebTokenHeader header, byte[] encryptedKey, CancellationToken cancellationToken) => throw new NotSupportedException();
        public Task<byte[]> AgreeKeyAsync(string keyId, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken) => throw new NotSupportedException();
        public IAsyncEnumerable<KeyVersion> GetKeyVersionsAsync(string keyName, CancellationToken cancellationToken) => throw new NotSupportedException();
    }

    [Fact]
    public void HostPreRegistrationWins()
    {
        IKeyCustodian custodian = new HostCustodian();
        var services = Configure();
        services.AddSingleton(custodian);
        services.AddVaultCustodian(options => options.Address = "https://vault.test:8200")
            .HoldKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "k" });

        using var provider = services.BuildServiceProvider();

        // The library registers after the host here, and the host still keeps its own: the repo's DI rule holds
        // regardless of call order.
        Assert.Same(custodian, provider.GetRequiredService<IKeyCustodian>());
    }
}
