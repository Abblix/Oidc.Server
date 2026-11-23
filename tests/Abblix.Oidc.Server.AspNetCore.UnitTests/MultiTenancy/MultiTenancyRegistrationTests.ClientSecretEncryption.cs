// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

public partial class MultiTenancyRegistrationTests
{
    private static TenantDefinition AcmeKeyed(bool keyed) => new()
    {
        Id = "acme",
        Issuer = new Uri(AcmeIssuer),
        ClientSecretEncryption = keyed
            ? new ClientSecretEncryptionSettings { Key = Convert.ToBase64String(RandomNumberGenerator.GetBytes(32)) }
            : null,
    };

    /// <summary>
    /// A server serving dynamic client registration gives a client reading its registration its secret back (RFC 7592
    /// section 3), so a tenant the settings declare without the key its secret is kept encrypted with stops the start,
    /// and the refusal names the tenant and the setting.
    /// </summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public void ATenantWithoutTheClientSecretKey_StopsTheStart_WhileRegistrationIsServed(bool keyed, bool refused)
    {
        var tenant = AcmeKeyed(keyed);
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddDynamicClientRegistration();
        services.AddClientInformation();
        services.AddServerStorage().ServeTenants(options => options.Tenants.Add(tenant));
        using var provider = services.BuildServiceProvider();

        var read = Record.Exception(() => provider.GetRequiredService<IOptions<OidcOptions>>().Value);

        Assert.Equal(refused, read is OptionsValidationException);
        if (refused)
        {
            Assert.Contains($"Tenant '{tenant.Id}': ", read!.Message, StringComparison.Ordinal);
            Assert.Contains(nameof(TenantDefinition.ClientSecretEncryption), read.Message, StringComparison.Ordinal);
        }
    }

    /// <summary>
    /// A tenant a store of tenants hands over without the key is refused as any tenant the checks refuse, and not
    /// served, while the server serves dynamic client registration.
    /// </summary>
    [Theory]
    [InlineData(false, true)]
    [InlineData(true, false)]
    public async Task AStoredTenantWithoutTheClientSecretKey_IsNotServed_WhileRegistrationIsServed(
        bool keyed,
        bool refused)
    {
        var store = new ChangingTenantStore { Tenants = [new StoredTenant(AcmeKeyed(keyed), "1")] };
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions<OidcOptions>();
        services.AddDynamicClientRegistration();
        services.AddClientInformation();
        services.AddSingleton<ITenantStore>(store);
        services.AddSingleton<TimeProvider>(new FakeTimeProvider());
        services.AddServerStorage().ServeTenants(_ => { });
        using var provider = services.BuildServiceProvider();

        var catalog = provider.GetRequiredService<StoreTenantCatalog>();
        await catalog.RefreshAsync(CancellationToken.None);

        Assert.Equal(refused, await catalog.FindByIdAsync("acme", CancellationToken.None) is null);
    }
}
