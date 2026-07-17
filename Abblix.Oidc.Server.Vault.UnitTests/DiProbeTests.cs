using Abblix.Jwt;
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.Vault.UnitTests;

public class DiProbeTests
{
    [Fact]
    public void CustodianIsSharedAcrossConsumers()
    {
        var services = new ServiceCollection();
        services.AddJsonWebTokens();
        services.AddVaultCustodian(o => o.Address = "https://vault.test:8200")
            .HoldKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "k" });
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);

        using var provider = services.BuildServiceProvider();
        Assert.Same(provider.GetRequiredService<IKeyCustodian>(), provider.GetRequiredService<IKeyCustodian>());
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
        var services = new ServiceCollection();
        services.AddJsonWebTokens();
        services.AddSingleton(custodian);
        services.AddVaultCustodian(o => o.Address = "https://vault.test:8200")
            .HoldKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "k" });
        services.AddOptions();
        services.AddSingleton(TimeProvider.System);

        using var provider = services.BuildServiceProvider();
        Assert.Same(custodian, provider.GetRequiredService<IKeyCustodian>());
    }
}
