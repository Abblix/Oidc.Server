// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
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
    private const string AcmeIssuer = "https://acme.example.com";

    private static readonly TenantDefinition Acme = new() { Id = "acme", Issuer = AcmeIssuer };

    private static ServiceProvider BuildProvider(bool multiTenancyFirst = false)
    {
        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        if (multiTenancyFirst)
            services.AddMultiTenancy(options => options.Tenants.Add(Acme));

        // The library's own issuer registration, not a stand-in, since it is what AddMultiTenancy has to win over.
        services.AddIssuer();

        if (!multiTenancyFirst)
            services.AddMultiTenancy(options => options.Tenants.Add(Acme));

        return services.BuildServiceProvider();
    }

    private static void EnterTenant(IServiceProvider provider, TenantDefinition? tenant)
    {
        var context = new DefaultHttpContext();
        if (tenant is not null)
            context.Features.Set(new TenantContext { Tenant = tenant });

        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
    }

    /// <summary>
    /// The issuer is the one the tenant declares, whichever order the host registers the two in.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public void UnderATenant_TheIssuerIsTheOneItDeclares(bool multiTenancyFirst)
    {
        using var provider = BuildProvider(multiTenancyFirst);
        EnterTenant(provider, Acme);

        Assert.Equal(AcmeIssuer, provider.GetRequiredService<IIssuerProvider>().GetIssuer());
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
        services.AddMultiTenancy(options => options.Tenants.Add(Acme));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains(nameof(OidcOptions.Issuer), refusal.Message, StringComparison.Ordinal);
    }

    [Fact]
    public async Task TheCatalog_FindsATenantByIdExactly_AndByAnySpellingOfItsHost()
    {
        var services = new ServiceCollection();
        services.AddMultiTenancy(options => options.Tenants.Add(
            new TenantDefinition { Id = "acme", Issuer = AcmeIssuer, Hosts = ["acme.example.com"] }));
        await using var provider = services.BuildServiceProvider();
        var catalog = provider.GetRequiredService<ITenantCatalog>();
        var cancellationToken = TestContext.Current.CancellationToken;

        Assert.Equal("acme", (await catalog.FindByIdAsync("acme", cancellationToken))?.Id);
        Assert.Null(await catalog.FindByIdAsync("ACME", cancellationToken));
        Assert.Equal("acme", (await catalog.FindByHostAsync("ACME.example.com.", cancellationToken))?.Id);
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
        Assert.True(TenantRequirement.IsUnmet(new DefaultHttpContext { RequestServices = multiTenant }));

        var resolved = new DefaultHttpContext { RequestServices = multiTenant };
        resolved.Features.Set(new TenantContext { Tenant = Acme });
        Assert.False(TenantRequirement.IsUnmet(resolved));
    }
}
