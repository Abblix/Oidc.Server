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
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// What <see cref="MultiTenancyExtensions.AddMultiTenancy"/> puts in the container, and the issuer a request
/// gets through it.
/// </summary>
public class MultiTenancyRegistrationTests
{
    private const string HostIssuer = "https://auth.example.com/t/acme";

    private static ServiceProvider BuildProvider(Action<MultiTenancyOptions>? configure = null)
    {
        var inner = new Mock<IIssuerProvider>();
        inner.Setup(p => p.GetIssuer()).Returns(HostIssuer);

        var services = new ServiceCollection();
        services.AddOptions<OidcOptions>();
        services.AddSingleton(inner.Object);
        services.AddMultiTenancy(configure ?? (options => options.Tenants.Add(new TenantDefinition { Id = "acme" })));
        return services.BuildServiceProvider();
    }

    private static void EnterTenant(IServiceProvider provider, string? tenantId)
    {
        var context = new DefaultHttpContext();
        if (tenantId is not null)
            context.Features.Set(new TenantContext(tenantId));

        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
    }

    [Fact]
    public void UnderATenant_TheIssuerIsTheOneTheDecoratedProviderNames()
    {
        using var provider = BuildProvider();
        EnterTenant(provider, "acme");

        Assert.Equal(HostIssuer, provider.GetRequiredService<IIssuerProvider>().GetIssuer());
    }

    /// <summary>
    /// A request that reached the server without a tenant has no issuer of its own; answering with the bare host
    /// would mint tokens every tenant on that host accepts.
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
        services.AddSingleton(Mock.Of<IIssuerProvider>());
        services.AddMultiTenancy(options => options.Tenants.Add(new TenantDefinition { Id = "acme" }));
        using var provider = services.BuildServiceProvider();

        var refusal = Assert.Throws<OptionsValidationException>(
            () => provider.GetRequiredService<IOptions<OidcOptions>>().Value);
        Assert.Contains(nameof(OidcOptions.Issuer), refusal.Message, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("a/b", "one non-empty path segment")]
    [InlineData("", "one non-empty path segment")]
    public void ATenantIdThatIsNotOnePathSegment_IsRefused(string tenantId, string expected)
    {
        var result = new MultiTenancyOptionsValidator().Validate(
            null, new MultiTenancyOptions { Tenants = [new TenantDefinition { Id = tenantId }] });

        Assert.True(result.Failed);
        Assert.Contains(expected, result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void ATenantIdDeclaredTwice_IsRefused()
    {
        var result = new MultiTenancyOptionsValidator().Validate(
            null,
            new MultiTenancyOptions
            {
                Tenants = [new TenantDefinition { Id = "acme" }, new TenantDefinition { Id = "acme" }],
            });

        Assert.True(result.Failed);
        Assert.Contains("declared more than once", result.FailureMessage, StringComparison.Ordinal);
    }

    /// <summary>
    /// Host names are compared without regard to case when a request is resolved, so two spellings of one
    /// host are one binding.
    /// </summary>
    [Fact]
    public void AHostBoundToTwoTenants_IsRefused_WhateverItsCase()
    {
        var result = new MultiTenancyOptionsValidator().Validate(
            null,
            new MultiTenancyOptions
            {
                Tenants =
                [
                    new TenantDefinition { Id = "acme", Hosts = ["login.example.com"] },
                    new TenantDefinition { Id = "globex", Hosts = ["Login.Example.com"] },
                ],
            });

        Assert.True(result.Failed);
        Assert.Contains("bound to more than one tenant", result.FailureMessage, StringComparison.Ordinal);
    }

    [Theory]
    [InlineData("")]
    [InlineData("t/x")]
    public void APathSegmentThatIsNotOneSegment_IsRefused(string segment)
    {
        var result = new MultiTenancyOptionsValidator().Validate(
            null, new MultiTenancyOptions { PathSegment = segment });

        Assert.True(result.Failed);
        Assert.Contains(nameof(MultiTenancyOptions.PathSegment), result.FailureMessage, StringComparison.Ordinal);
    }

    [Fact]
    public void AValidTenantList_IsAccepted()
    {
        var result = new MultiTenancyOptionsValidator().Validate(
            null,
            new MultiTenancyOptions
            {
                Tenants =
                [
                    new TenantDefinition { Id = "acme", Hosts = ["acme.example.com"] },
                    new TenantDefinition { Id = "globex" },
                ],
            });

        Assert.True(result.Succeeded);
    }

    [Fact]
    public async Task TheCatalog_FindsATenantByIdExactly_AndByHostWithoutRegardToCase()
    {
        await using var provider = BuildProvider(options =>
            options.Tenants.Add(new TenantDefinition { Id = "acme", Hosts = ["acme.example.com"] }));
        var catalog = provider.GetRequiredService<ITenantCatalog>();

        Assert.Equal("acme", (await catalog.FindByIdAsync("acme"))?.Id);
        Assert.Null(await catalog.FindByIdAsync("ACME"));
        Assert.Equal("acme", (await catalog.FindByHostAsync("ACME.example.com"))?.Id);
    }
}
