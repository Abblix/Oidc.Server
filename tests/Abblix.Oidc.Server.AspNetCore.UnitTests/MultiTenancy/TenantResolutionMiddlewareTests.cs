// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Threading.Tasks;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

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
            new TenantDefinition { Id = "acme", Hosts = [BoundHost] },
            new TenantDefinition { Id = "globex" },
        ],
    };

    /// <summary>What the rest of the pipeline saw, recorded while it ran.</summary>
    private sealed record Seen(TenantContext? Tenant, string PathBase, string Path);

    private async Task<(HttpContext Context, Seen? Seen)> RunAsync(string host, string path)
    {
        var monitor = new Mock<IOptionsMonitor<MultiTenancyOptions>>();
        monitor.SetupGet(m => m.CurrentValue).Returns(_options);

        Seen? seen = null;
        var middleware = new TenantResolutionMiddleware(
            context =>
            {
                seen = new Seen(
                    context.Features.Get<TenantContext>(), context.Request.PathBase.Value ?? string.Empty,
                    context.Request.Path.Value ?? string.Empty);
                return Task.CompletedTask;
            },
            new OptionsTenantCatalog(monitor.Object),
            monitor.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Host = new HostString(host);
        httpContext.Request.Path = path;

        await middleware.InvokeAsync(httpContext);
        return (httpContext, seen);
    }

    [Fact]
    public async Task AHostBoundToATenant_ResolvesToIt_AndLeavesThePathAlone()
    {
        var (_, seen) = await RunAsync(BoundHost, "/connect/token");

        Assert.Equal(new Seen(new TenantContext("acme"), string.Empty, "/connect/token"), seen);
    }

    [Fact]
    public async Task APathNamingATenant_ResolvesToIt_WithTheTenantMovedIntoThePathBase()
    {
        var (context, seen) = await RunAsync(SharedHost, "/t/globex/connect/token");

        Assert.Equal(new Seen(new TenantContext("globex"), "/t/globex", "/connect/token"), seen);

        // And the request is handed back as it came, for whatever runs after this pipeline returns.
        Assert.Equal(string.Empty, context.Request.PathBase.Value ?? string.Empty);
        Assert.Equal("/t/globex/connect/token", context.Request.Path.Value);
    }

    [Fact]
    public async Task APathNamingOnlyTheTenant_ResolvesToIt_WithAnEmptyPath()
    {
        var (_, seen) = await RunAsync(SharedHost, "/t/globex");

        Assert.Equal(new Seen(new TenantContext("globex"), "/t/globex", string.Empty), seen);
    }

    /// <summary>
    /// A host bound to a tenant decides it, so a path naming another tenant on that host is not followed:
    /// otherwise one request could be resolved two ways.
    /// </summary>
    [Fact]
    public async Task APathNamingAnotherTenantOnABoundHost_IsNotFollowed()
    {
        var (_, seen) = await RunAsync(BoundHost, "/t/globex/connect/token");

        Assert.Equal(new Seen(new TenantContext("acme"), string.Empty, "/t/globex/connect/token"), seen);
    }

    [Fact]
    public async Task APathNamingAnUndeclaredTenant_IsAnswered404_BeforeAnyEndpoint()
    {
        var (context, seen) = await RunAsync(SharedHost, "/t/initech/connect/token");

        Assert.Null(seen);
        Assert.Equal(StatusCodes.Status404NotFound, context.Response.StatusCode);
    }

    [Theory]
    [InlineData("/connect/token")]
    [InlineData("/t")]
    [InlineData("/t/")]
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
