// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// A host whose custodian cannot serve the key management algorithm it configured stops at startup, and the same host
/// with an algorithm the custodian serves starts, so the refusal is the algorithm's and not the custodian's.
/// </summary>
public class KeyManagementAlgorithmCheckTests
{
    private const string Served = EncryptionAlgorithms.KeyManagement.RsaOaep256;
    private const string NotServed = EncryptionAlgorithms.KeyManagement.RsaOaep;

    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task AnEncryptionKeyUnderAnAlgorithmTheCustodianDoesNotServe_StopsTheHost(bool fromFactory)
    {
        var services = HostWithCustodian();
        var keys = KeysEncryptingUnder(NotServed);
        if (fromFactory)
            services.RequireKeyPlacement().UseKeysInCustodian(_ => keys);
        else
            services.RequireKeyPlacement().UseKeysInCustodian(keys);

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(services));

        Assert.Contains(NotServed, Assert.Single(error.Failures), StringComparison.Ordinal);
    }

    [Fact]
    public async Task AnEncryptionKeyUnderAnAlgorithmTheCustodianServes_Starts()
    {
        var services = HostWithCustodian();
        services.RequireKeyPlacement().UseKeysInCustodian(KeysEncryptingUnder(Served));

        await StartAsync(services);
    }

    /// <summary>
    /// The algorithm has no effect while no encryption key is named, so it cannot stop a signing-only host.
    /// </summary>
    [Fact]
    public async Task AnAlgorithmWithNoEncryptionKey_Starts()
    {
        var services = HostWithCustodian();
        services.RequireKeyPlacement().UseKeysInCustodian(
            new CustodianHeldKeys { SigningKeyName = "sign", EncryptionAlgorithm = NotServed });

        await StartAsync(services);
    }

    [Theory]
    [InlineData(NotServed, false)]
    [InlineData(Served, true)]
    public async Task AKeyRingSealingUnderAnAlgorithm_StartsOnlyWhenTheCustodianServesIt(string keyWrap, bool starts)
    {
        var services = HostWithCustodian();
        services
            .RequireKeyPlacement()
            .UseKeysInProcess(new MintedKeys { KeyEncryptionKeyName = "kek", KeyWrapAlgorithm = keyWrap })
            .Services.AddSingleton(Mock.Of<IKeyRingStore>());

        if (starts)
        {
            await StartAsync(services);
            return;
        }

        var error = await Assert.ThrowsAsync<OptionsValidationException>(() => StartAsync(services));
        Assert.Contains(keyWrap, Assert.Single(error.Failures), StringComparison.Ordinal);
    }

    private static CustodianHeldKeys KeysEncryptingUnder(string algorithm) => new()
    {
        SigningKeyName = "sign",
        EncryptionKeyName = "encrypt",
        EncryptionAlgorithm = algorithm,
    };

    /// <summary>A host whose custodian serves one key management algorithm, as Vault Transit does.</summary>
    private static ServiceCollection HostWithCustodian()
    {
        var custodian = new Mock<IKeyCustodian>();
        custodian.Setup(c => c.ServesKeyManagement(It.IsAny<string>())).Returns<string>(algorithm => algorithm == Served);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton(custodian.Object);
        services.AddJsonWebTokens();
        return services;
    }

    private static async Task StartAsync(IServiceCollection services)
    {
        await using var provider = services.BuildServiceProvider();
        await provider.GetRequiredService<IAsyncStartupValidator>().ValidateAsync(TestContext.Current.CancellationToken);
    }
}
