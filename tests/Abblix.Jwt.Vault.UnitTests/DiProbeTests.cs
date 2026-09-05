// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// Covers what only a built provider can answer: how many of each service a host actually ends up with, and whose
/// registration wins. Both are invisible in the registration code and silent at runtime when wrong.
/// </summary>
public class DiProbeTests
{
    private static IServiceCollection Configure()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);
        return services;
    }

    [Fact]
    public void CustodianIsSharedAcrossConsumers()
    {
        var services = Configure();
        services.AddVaultCustodian(options => options.Address = "https://vault.test:8200");

        using var provider = services.BuildServiceProvider();

        // One custodian, however many services consume it. A per-consumer custodian would work in every test and
        // still be wrong in production: each copy carries its own credential and its own caches.
        Assert.Same(provider.GetRequiredService<IKeyCustodian>(), provider.GetRequiredService<IKeyCustodian>());
    }

    [Fact]
    public void CustodianAndKeyRingShareOneTransport()
    {
        var services = Configure();
        services.AddVaultCustodian(options => options.Address = "https://vault.test:8200");

        // Reached through the JWT layer's ring registration rather than the server's placement call: this
        // package no longer depends on the server, and this is the path any other consumer takes.
        services
            .AddKeyRing(new MintedKeys { KeyEncryptionKeyName = "oidc-kek" })
            .PersistRingToVaultKeyValue();

        // Both engines wire the transport, but it must land once: AddHttpClient appends, so a second wiring would
        // stack a second token handler on every request. The token handler's single registration is that
        // guarantee, and nothing at runtime would report a doubled one.
        Assert.Equal(1, services.Count(descriptor => descriptor.ServiceType == typeof(TokenHandler)));

        using var provider = services.BuildServiceProvider();
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
        services.AddVaultCustodian(options => options.Address = "https://vault.test:8200");

        using var provider = services.BuildServiceProvider();

        // The library registers after the host here, and the host still keeps its own: the repo's DI rule holds
        // regardless of call order.
        Assert.Same(custodian, provider.GetRequiredService<IKeyCustodian>());
    }
}
