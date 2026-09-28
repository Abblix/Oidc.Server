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
using Xunit;

// The feature is marked experimental for its consumers; these tests are where it is built.
#pragma warning disable ABXMT001

namespace Abblix.Oidc.Server.AspNetCore.UnitTests.MultiTenancy;

/// <summary>
/// How <see cref="TenantResolutionMiddleware"/> resolves a request, observed from inside the pipeline it runs.
/// </summary>
public class TenantResolutionMiddlewareTests
{
    private const string OwnHost = "acme.example.com";
    private const string SharedHost = "auth.example.com";
    private const string MountedHost = "idp.example.com";

    private static readonly MultiTenancyOptions Declared = new()
    {
        Tenants =
        [
            new TenantDefinition { Id = "acme", Issuer = "https://acme.example.com" },
            new TenantDefinition { Id = "muenchen", Issuer = "https://münchen.example.com/" },
            new TenantDefinition { Id = "shared", Issuer = "https://auth.example.com" },
            new TenantDefinition { Id = "globex", Issuer = "https://auth.example.com/tenants/globex" },
            new TenantDefinition { Id = "globex-eu", Issuer = "https://auth.example.com/tenants/globex/eu/" },
            new TenantDefinition { Id = "initech", Issuer = "https://idp.example.com/idp/initech" },
        ],
    };

    /// <summary>What the rest of the pipeline saw, recorded while it ran.</summary>
    private sealed record Seen(string? TenantId, string PathBase, string Path);

    private static async Task<(HttpContext Context, Seen? Seen)> RunAsync(
        string host, string path, string pathBase = "", Exception? thrownDownstream = null)
    {
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
            new OptionsTenantCatalog(Options.Create(Declared)));

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
    public async Task ATenantServingAWholeHost_IsResolvedThere_WithThePathLeftAlone()
    {
        var (context, seen) = await RunAsync(OwnHost, "/connect/token");

        Assert.Equal(new Seen("acme", string.Empty, "/connect/token"), seen);
        Assert.True(TenantResolutionMiddleware.HasRun(context));
    }

    /// <summary>
    /// A request can spell one host several ways, and an issuer compared as written would be missed by all but
    /// one of them.
    /// </summary>
    [Theory]
    [InlineData("ACME.example.com", "acme")]
    [InlineData("acme.example.com.", "acme")]
    [InlineData("xn--mnchen-3ya.example.com", "muenchen")]
    [InlineData("münchen.example.com", "muenchen")]
    public async Task AnotherSpellingOfTheIssuersHost_ResolvesToTheSameTenant(string host, string tenantId)
    {
        var (_, seen) = await RunAsync(host, "/connect/token");

        Assert.Equal(new Seen(tenantId, string.Empty, "/connect/token"), seen);
    }

    [Fact]
    public async Task ARequestUnderAnIssuersPath_ResolvesToIt_WithThatPathMovedIntoThePathBase()
    {
        var (context, seen) = await RunAsync(SharedHost, "/tenants/globex/connect/token");

        Assert.Equal(new Seen("globex", "/tenants/globex", "/connect/token"), seen);

        // And the request is handed back as it came, for whatever runs after this pipeline returns.
        Assert.Equal(string.Empty, context.Request.PathBase.Value ?? string.Empty);
        Assert.Equal("/tenants/globex/connect/token", context.Request.Path.Value);
    }

    [Fact]
    public async Task TheRequestIsHandedBack_EvenWhenThePipelineFails()
    {
        var failure = new InvalidOperationException("downstream");

        var (context, _) = await RunAsync(SharedHost, "/tenants/globex/connect/token", thrownDownstream: failure);

        Assert.Equal(string.Empty, context.Request.PathBase.Value ?? string.Empty);
        Assert.Equal("/tenants/globex/connect/token", context.Request.Path.Value);
    }

    [Theory]
    [InlineData("/tenants/globex", "globex", "/tenants/globex", "")]
    [InlineData("/tenants/globex/.well-known/openid-configuration", "globex", "/tenants/globex", "/.well-known/openid-configuration")]
    [InlineData("/tenants/globex/eu/connect/token", "globex-eu", "/tenants/globex/eu", "/connect/token")]
    [InlineData("/tenants/globex/eu", "globex-eu", "/tenants/globex/eu", "")]
    public async Task TheLongestIssuerPathStartingTheRequest_Wins(
        string path, string tenantId, string pathBase, string rest)
    {
        var (_, seen) = await RunAsync(SharedHost, path);

        Assert.Equal(new Seen(tenantId, pathBase, rest), seen);
    }

    /// <summary>
    /// An issuer path covers only whole segments, spelled exactly: a browser compares cookie paths exactly too,
    /// so a tenant reached through <c>/Tenants/</c> would never be sent the cookie set under <c>/tenants/</c>.
    /// A path only the issuer at the root of the host covers belongs to that tenant - a well-known path too,
    /// unless the inserted form names an issuer exactly: anything longer is some other address under the suffix.
    /// </summary>
    [Theory]
    [InlineData("/connect/token")]
    [InlineData("/tenants/globex2/connect/token")]
    [InlineData("/tenants/globexeu")]
    [InlineData("/Tenants/globex/connect/token")]
    [InlineData("/tenants")]
    [InlineData("/.well-known/oauth-authorization-server/tenants/globex/extra")]
    [InlineData("/.well-known/oauth-authorization-server/tenants/initech")]
    [InlineData("/.well-known/oauth-authorization-server")]
    [InlineData("/.well-known/oauth-authorization-server/")]
    public async Task APathOnlyTheRootIssuerCovers_BelongsToTheTenantAtTheRootOfTheHost(string path)
    {
        var (_, seen) = await RunAsync(SharedHost, path);

        Assert.Equal(new Seen("shared", string.Empty, path), seen);
    }

    [Fact]
    public async Task AHostNoIssuerNames_PassesThroughWithoutATenant()
    {
        var (context, seen) = await RunAsync("other.example.com", "/tenants/globex/connect/token");

        Assert.Equal(new Seen(null, string.Empty, "/tenants/globex/connect/token"), seen);
        Assert.True(TenantResolutionMiddleware.HasRun(context));
    }

    [Fact]
    public async Task UnderAnApplicationPathBase_TheIssuersPathExtendsIt()
    {
        var (_, seen) = await RunAsync(MountedHost, "/initech/connect/token", pathBase: "/idp");

        Assert.Equal(new Seen("initech", "/idp/initech", "/connect/token"), seen);
    }

    /// <summary>
    /// An issuer above the path base the application is mounted under names addresses this server is not
    /// reached at, so it resolves nothing there.
    /// </summary>
    [Fact]
    public async Task AnIssuerAboveTheApplicationPathBase_ResolvesNothing()
    {
        var (_, seen) = await RunAsync(SharedHost, "/connect/token", pathBase: "/idp");

        Assert.Equal(new Seen(null, "/idp", "/connect/token"), seen);
    }

    /// <summary>
    /// RFC 8414 section 3.1 inserts the well-known suffix between the host and the issuer's path.
    /// </summary>
    [Theory]
    [InlineData("/.well-known/oauth-authorization-server/tenants/globex", "globex", "/tenants/globex", "/.well-known/oauth-authorization-server")]
    [InlineData("/.well-known/openid-configuration/tenants/globex/eu", "globex-eu", "/tenants/globex/eu", "/.well-known/openid-configuration")]
    public async Task TheInsertedWellKnownForm_ReachesTheIssuersMetadata_AndIsHandedBackAsItCame(
        string path, string tenantId, string pathBase, string rest)
    {
        var (context, seen) = await RunAsync(SharedHost, path);

        Assert.Equal(new Seen(tenantId, pathBase, rest), seen);
        Assert.Equal(string.Empty, context.Request.PathBase.Value ?? string.Empty);
        Assert.Equal(path, context.Request.Path.Value);
    }

    /// <summary>
    /// RFC 8414 places the inserted form at the root of the host; under a path base it is an ordinary path.
    /// </summary>
    [Fact]
    public async Task TheInsertedWellKnownForm_IsNotReadUnderAPathBase()
    {
        var (_, seen) = await RunAsync(MountedHost, "/.well-known/oauth-authorization-server/idp/initech", pathBase: "/idp");

        Assert.Equal(new Seen(null, "/idp", "/.well-known/oauth-authorization-server/idp/initech"), seen);
    }
}
