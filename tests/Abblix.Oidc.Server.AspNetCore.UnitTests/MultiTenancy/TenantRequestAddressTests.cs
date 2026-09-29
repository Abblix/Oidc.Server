// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// The addresses a request under a path tenant yields, against the same request without multi-tenancy, which
/// must yield what it always did.
/// </summary>
public class TenantRequestAddressTests
{
    private static HttpContext Request(bool underTenant)
    {
        var services = new ServiceCollection();
        services.AddHttpContextAccessor();
        if (underTenant)
            services.AddSingleton<ITenantAccessor, HttpContextTenantAccessor>();
        var provider = services.BuildServiceProvider();

        var context = new DefaultHttpContext { RequestServices = provider };
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("auth.example.com");
        context.Request.PathBase = "/tenants/globex";
        context.Request.Path = "/connect/token";
        if (underTenant)
        {
            context.Features.Set(new TenantContext
            {
                Tenant = new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/tenants/globex" },
            });
        }

        provider.GetRequiredService<IHttpContextAccessor>().HttpContext = context;
        return context;
    }

    private static string RequestUriOf(HttpContext context)
        => new HttpRequestInfoProvider(new HttpContextAccessor { HttpContext = context }).RequestUri;

    /// <summary>
    /// The address a DPoP proof's htu and a client assertion's aud are checked against is the one discovery
    /// advertises for the tenant, path base included.
    /// </summary>
    [Fact]
    public void UnderATenant_TheRequestAddressCarriesThePathBase()
        => Assert.Equal("https://auth.example.com/tenants/globex/connect/token", RequestUriOf(Request(underTenant: true)));

    [Fact]
    public void WithoutATenant_TheRequestAddressIsWhatItAlwaysWas()
        => Assert.Equal("https://auth.example.com/connect/token", RequestUriOf(Request(underTenant: false)));

    /// <summary>
    /// Under a tenant every relative address is the tenant's: a login page addressed from the root would run
    /// without the tenant, and the MVC transport advertises endpoints by route templates that carry no leading
    /// slash. Without tenants both resolve as they always did.
    /// </summary>
    [Theory]
    [InlineData(true, "/Auth/Login", "https://auth.example.com/tenants/globex/Auth/Login")]
    [InlineData(true, "connect/token", "https://auth.example.com/tenants/globex/connect/token")]
    [InlineData(false, "/Auth/Login", "https://auth.example.com/Auth/Login")]
    [InlineData(false, "connect/token", "https://auth.example.com/tenants/connect/token")]
    public void ARelativeAddress_IsTheTenants_OnlyUnderATenant(bool underTenant, string path, string expected)
        => Assert.Equal(new Uri(expected), Request(underTenant).Request.ResolveInteractionUri(path));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AnApplicationRelativeAddress_IsTheApplicationBases_EitherWay(bool underTenant)
        => Assert.Equal(
            new Uri("https://auth.example.com/tenants/globex/Auth/Login"),
            Request(underTenant).Request.ResolveInteractionUri("~/Auth/Login"));

    /// <summary>
    /// An address naming another host stays there, whether it names it with a scheme, without one
    /// (<c>//host/path</c>), or in a form a browser accepts though it is not strictly well formed.
    /// </summary>
    [Theory]
    [InlineData(true, "https://login.example.org/Auth/Login", "https://login.example.org/Auth/Login")]
    [InlineData(false, "https://login.example.org/Auth/Login", "https://login.example.org/Auth/Login")]
    [InlineData(true, "//login.example.org/Auth/Login", "https://login.example.org/Auth/Login")]
    [InlineData(false, "//login.example.org/Auth/Login", "https://login.example.org/Auth/Login")]
    [InlineData(true, "https://login.example.org/Auth/Log in", "https://login.example.org/Auth/Log%20in")]
    public void AnAddressOnAnotherHost_StaysThere_EitherWay(bool underTenant, string path, string expected)
        => Assert.Equal(new Uri(expected), Request(underTenant).Request.ResolveInteractionUri(path));
}
