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
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// How <see cref="TenantResolutionMiddleware"/> resolves a request, observed from inside the pipeline it runs.
/// </summary>
public class TenantResolutionMiddlewareTests
{
    private const string BoundHost = "acme.example.com";
    private const string SharedHost = "auth.example.com";

    private readonly MultiTenancyOptions _options = new()
    {
        Tenants =
        [
            new TenantDefinition { Id = "acme", Issuer = "https://acme.example.com", Hosts = [BoundHost, "münchen.example.com"] },
            new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/t/globex" },
        ],
    };

    /// <summary>What the rest of the pipeline saw, recorded while it ran.</summary>
    private sealed record Seen(string? TenantId, string PathBase, string Path);

    private async Task<(HttpContext Context, Seen? Seen)> RunAsync(
        string host, string path, string pathBase = "", Exception? thrownDownstream = null)
    {
        var monitor = new Mock<IOptionsMonitor<MultiTenancyOptions>>();
        monitor.SetupGet(m => m.CurrentValue).Returns(_options);

        Seen? seen = null;
        var middleware = new TenantResolutionMiddleware(
            context =>
            {
                seen = new Seen(
                    context.Features.Get<TenantContext>()?.Tenant.Id,
                    context.Request.PathBase.Value ?? string.Empty,
                    context.Request.Path.Value ?? string.Empty);
                return thrownDownstream is null ? Task.CompletedTask : Task.FromException(thrownDownstream);
            },
            new OptionsTenantCatalog(monitor.Object),
            monitor.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Host = new HostString(host);
        httpContext.Request.PathBase = pathBase;
        httpContext.Request.Path = path;

        try
        {
            await middleware.InvokeAsync(httpContext);
        }
        catch (Exception exception) when (exception == thrownDownstream)
        {
            // Asserted by the caller through the request it gets back.
        }

        return (httpContext, seen);
    }

    [Fact]
    public async Task AHostBoundToATenant_ResolvesToIt_AndLeavesThePathAlone()
    {
        var (_, seen) = await RunAsync(BoundHost, "/connect/token");

        Assert.Equal(new Seen("acme", string.Empty, "/connect/token"), seen);
    }

    /// <summary>
    /// A request can spell one host several ways, and a binding missed by any of them would let a path choose
    /// another tenant on that host.
    /// </summary>
    [Theory]
    [InlineData("ACME.example.com")]
    [InlineData("acme.example.com.")]
    [InlineData("xn--mnchen-3ya.example.com")]
    public async Task AnotherSpellingOfABoundHost_ResolvesToTheSameTenant_AndStillBindsIt(string host)
    {
        var (_, seen) = await RunAsync(host, "/t/globex/connect/token");

        Assert.Equal(new Seen("acme", string.Empty, "/t/globex/connect/token"), seen);
    }

    [Fact]
    public async Task APathNamingATenant_ResolvesToIt_WithTheTenantMovedIntoThePathBase()
    {
        var (context, seen) = await RunAsync(SharedHost, "/t/globex/connect/token");

        Assert.Equal(new Seen("globex", "/t/globex", "/connect/token"), seen);

        // And the request is handed back as it came, for whatever runs after this pipeline returns.
        Assert.Equal(string.Empty, context.Request.PathBase.Value ?? string.Empty);
        Assert.Equal("/t/globex/connect/token", context.Request.Path.Value);
    }

    [Fact]
    public async Task APathNamingATenant_UnderAnApplicationPathBase_AppendsTheTenantToIt()
    {
        var (_, seen) = await RunAsync(SharedHost, "/t/globex/connect/token", pathBase: "/idp");

        Assert.Equal(new Seen("globex", "/idp/t/globex", "/connect/token"), seen);
    }

    [Fact]
    public async Task TheRequestIsHandedBack_EvenWhenThePipelineFails()
    {
        var failure = new InvalidOperationException("downstream");

        var (context, _) = await RunAsync(SharedHost, "/t/globex/connect/token", thrownDownstream: failure);

        Assert.Equal(string.Empty, context.Request.PathBase.Value ?? string.Empty);
        Assert.Equal("/t/globex/connect/token", context.Request.Path.Value);
    }

    [Fact]
    public async Task APathNamingOnlyTheTenant_ResolvesToIt_WithAnEmptyPath()
    {
        var (_, seen) = await RunAsync(SharedHost, "/t/globex");

        Assert.Equal(new Seen("globex", "/t/globex", string.Empty), seen);
    }

    /// <summary>
    /// A host bound to a tenant decides it, so a path naming another tenant on that host is not followed:
    /// otherwise one request could be resolved two ways.
    /// </summary>
    [Fact]
    public async Task APathNamingAnotherTenantOnABoundHost_IsNotFollowed()
    {
        var (_, seen) = await RunAsync(BoundHost, "/t/globex/connect/token");

        Assert.Equal(new Seen("acme", string.Empty, "/t/globex/connect/token"), seen);
    }

    [Fact]
    public async Task APathNamingAnUndeclaredTenant_IsAnswered404_BeforeAnyEndpoint()
    {
        var (context, seen) = await RunAsync(SharedHost, "/t/initech/connect/token");

        Assert.Null(seen);
        Assert.Equal(StatusCodes.Status404NotFound, context.Response.StatusCode);
    }

    /// <summary>
    /// The segment is compared exactly: a browser compares cookie paths exactly too, so a tenant reached through
    /// <c>/T/</c> would never be sent the cookie set under <c>/t/</c>.
    /// </summary>
    [Theory]
    [InlineData("/connect/token")]
    [InlineData("/t")]
    [InlineData("/t/")]
    [InlineData("/t//connect/token")]
    [InlineData("/T/globex/connect/token")]
    [InlineData("/tenants/globex")]
    public async Task ARequestNamingNoTenant_PassesThroughWithoutOne(string path)
    {
        var (_, seen) = await RunAsync(SharedHost, path);

        Assert.Equal(new Seen(null, string.Empty, path), seen);
    }

    [Fact]
    public async Task WithPathResolutionOff_APathNamingATenant_IsNotFollowed()
    {
        _options.PathSegment = null;

        var (_, seen) = await RunAsync(SharedHost, "/t/globex/connect/token");

        Assert.Equal(new Seen(null, string.Empty, "/t/globex/connect/token"), seen);
    }
}
