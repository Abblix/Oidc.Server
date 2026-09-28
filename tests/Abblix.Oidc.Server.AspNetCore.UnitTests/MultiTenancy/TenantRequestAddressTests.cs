// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
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
        var context = new DefaultHttpContext();
        context.Request.Scheme = "https";
        context.Request.Host = new HostString("auth.example.com");
        context.Request.PathBase = "/t/globex";
        context.Request.Path = "/connect/token";
        if (underTenant)
        {
            context.Features.Set(new TenantContext
            {
                Tenant = new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/t/globex" },
            });
        }

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
        => Assert.Equal("https://auth.example.com/t/globex/connect/token", RequestUriOf(Request(underTenant: true)));

    [Fact]
    public void WithoutATenant_TheRequestAddressIsWhatItAlwaysWas()
        => Assert.Equal("https://auth.example.com/connect/token", RequestUriOf(Request(underTenant: false)));

    /// <summary>
    /// A login page addressed from the root would run without the tenant, and its cookie, written for the root,
    /// would reach every tenant on the host.
    /// </summary>
    [Fact]
    public void UnderATenant_ARootedInteractionAddress_IsTheTenants()
        => Assert.Equal(
            new Uri("https://auth.example.com/t/globex/Auth/Login"),
            Request(underTenant: true).Request.ResolveInteractionUri("/Auth/Login"));

    [Fact]
    public void WithoutATenant_ARootedInteractionAddress_IsTheServerRoots()
        => Assert.Equal(
            new Uri("https://auth.example.com/Auth/Login"),
            Request(underTenant: false).Request.ResolveInteractionUri("/Auth/Login"));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AnApplicationRelativeInteractionAddress_IsTheApplicationBases_EitherWay(bool underTenant)
        => Assert.Equal(
            new Uri("https://auth.example.com/t/globex/Auth/Login"),
            Request(underTenant).Request.ResolveInteractionUri("~/Auth/Login"));

    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void AnAbsoluteInteractionAddress_IsKept_EitherWay(bool underTenant)
        => Assert.Equal(
            new Uri("https://login.example.org/Auth/Login"),
            Request(underTenant).Request.ResolveInteractionUri("https://login.example.org/Auth/Login"));
}
