// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

public partial class MultiTenancyRegistrationTests
{
    /// <summary>
    /// A key provider of the host's own that signs with the key ring, as a host wrapping the ring in a cache has.
    /// </summary>
    private sealed class RingKeysProvider(IKeyRing ring) : IAuthServiceKeysProvider
    {
        public IAsyncEnumerable<JsonWebKey> GetEncryptionKeys(TenantDefinition tenant, bool includePrivateKeys = false)
            => ring.Get(PublicKeyUsages.Encryption, includePrivateKeys).ToAsyncEnumerable();

        public IAsyncEnumerable<JsonWebKey> GetSigningKeys(TenantDefinition tenant, bool includePrivateKeys = false)
            => ring.Get(PublicKeyUsages.Signature, includePrivateKeys).ToAsyncEnumerable();
    }

    /// <summary>
    /// A host whose own key provider takes the key ring in its constructor starts, whether it registers the provider
    /// before or after the server and whichever of the two it reads first; its tenant declares no key, since the
    /// provider answers for each tenant's keys itself.
    /// </summary>
    [Theory]
    [InlineData(true, true)]
    [InlineData(true, false)]
    [InlineData(false, true)]
    [InlineData(false, false)]
    public async Task AHostsOwnKeyProviderOverTheKeyRing_Starts(bool registeredFirst, bool providerReadFirst)
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        if (registeredFirst)
            services.AddSingleton<IAuthServiceKeysProvider, RingKeysProvider>();

        services.AddAuthServiceJwt();
        services.AddInMemoryKeyRing(new LocalKeys());
        services.AddServerStorage().ServeTenants(options => options.Tenants.Add(Acme));

        if (!registeredFirst)
            services.AddSingleton<IAuthServiceKeysProvider, RingKeysProvider>();

        await using var provider = services.BuildServiceProvider();

        IAuthServiceKeysProvider keys;
        if (providerReadFirst)
        {
            keys = provider.GetRequiredService<IAuthServiceKeysProvider>();
            _ = provider.GetRequiredService<IOptions<OidcOptions>>().Value;
        }
        else
        {
            _ = provider.GetRequiredService<IOptions<OidcOptions>>().Value;
            keys = provider.GetRequiredService<IAuthServiceKeysProvider>();
        }

        Assert.IsType<RingKeysProvider>(keys);
        Assert.NotEmpty(await keys.GetSigningKeys(Acme).ToArrayAsync(TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// With the server minting its keys and a key provider of the host's own serving them, a tenant's keys are the
    /// host's to judge and its ring the host's to open: keys the tenant declares are not refused, and opening the
    /// tenant opens no ring.
    /// </summary>
    [Fact]
    public async Task AHostsOwnKeyProvider_OverMintedKeys_LeavesEachTenantsKeysAndRingToTheHost()
    {
        var acme = new TenantDefinition
        {
            Id = "acme",
            Issuer = new Uri(AcmeIssuer),
            EncryptionKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption)],
        };
        using var provider = MintingKeys(
            services => services.AddSingleton(Moq.Mock.Of<IAuthServiceKeysProvider>()),
            acme);

        Assert.Single(provider.GetRequiredService<IOptions<OidcOptions>>().Value.Tenants);

        var opening = provider.GetServices<ITenantOpening>().OfType<TenantKeyRingOpening>().Single();
        await opening.OpenAsync([acme], TestContext.Current.CancellationToken);

        Moq.Mock.Get(provider.GetRequiredService<IKeyRings>()).Verify(
            rings => rings.OpenAsync(Moq.It.IsAny<IReadOnlyCollection<string>>(), Moq.It.IsAny<CancellationToken>()),
            Moq.Times.Never);
    }

    /// <summary>
    /// A key provider the host registers under a key is not the one the server serves, so the server's own provider
    /// still judges each tenant's keys.
    /// </summary>
    [Fact]
    public void AKeyedKeyProviderOfTheHost_LeavesTheServersOwnProviderJudgingTheKeys()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddAuthServiceJwt();
        services.AddServerStorage().ServeTenants(options => options.Tenants.Add(Acme));
        services.AddKeyedSingleton("elsewhere", Moq.Mock.Of<IAuthServiceKeysProvider>());
        using var provider = services.BuildServiceProvider();

        var refusals = KeysCheckOf(provider).Check([Acme], new OidcOptions());

        Assert.Equal(["acme"], Assert.Single(refusals).TenantIds);
    }

    /// <summary>
    /// With no key provider registered at all, as tenants served without the token services have, no tenant's keys
    /// are judged, so a tenant declaring none is served.
    /// </summary>
    [Fact]
    public void WithoutAnyKeyProvider_NoTenantsKeysAreJudged()
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddServerStorage().ServeTenants(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        Assert.Empty(KeysCheckOf(provider).Check([Acme], new OidcOptions()));
    }

    private static TenantKeysCheck KeysCheckOf(IServiceProvider provider)
        => provider.GetServices<ITenantsCheck>().OfType<TenantKeysCheck>().Single();
}
