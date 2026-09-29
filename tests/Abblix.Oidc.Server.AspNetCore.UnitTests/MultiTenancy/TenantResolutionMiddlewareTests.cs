// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading;
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
            new TenantDefinition { Id = "societe", Issuer = "https://auth.example.com/tenants/société" },
            new TenantDefinition { Id = "spaced", Issuer = "https://auth.example.com/tenants/a b" },
            new TenantDefinition { Id = "slashed", Issuer = "https://auth.example.com/tenants/a%2Fb" },
            new TenantDefinition { Id = "slashed-lower", Issuer = "https://auth.example.com/tenants/c%2fd" },
            new TenantDefinition { Id = "mounted", Issuer = "https://idp.example.com/x%2fy/mounted" },
            new TenantDefinition { Id = "proxied", Issuer = "https://proxy.example.com/idp" },
            new TenantDefinition { Id = "proxy-root", Issuer = "https://proxy-root.example.com" },
            new TenantDefinition { Id = "loopback6", Issuer = "https://[::1]:8443/" },
            new TenantDefinition { Id = "loopback4", Issuer = "https://127.0.0.1/tenants/local" },
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

    /// <summary>
    /// The server hands the pipeline a decoded path, except for an encoded slash, which would otherwise split a
    /// segment; an issuer's path is compared in that same form.
    /// </summary>
    [Theory]
    [InlineData("/tenants/société/connect/token", "societe", "/tenants/société")]
    [InlineData("/tenants/a b/connect/token", "spaced", "/tenants/a b")]
    [InlineData("/tenants/a%2Fb/connect/token", "slashed", "/tenants/a%2Fb")]
    [InlineData("/tenants/a%2fb/connect/token", "slashed", "/tenants/a%2fb")]
    [InlineData("/.well-known/openid-configuration/tenants/a%2fb", "slashed", "/tenants/a%2fb")]
    [InlineData("/tenants/c%2Fd/connect/token", "slashed-lower", "/tenants/c%2Fd")]
    [InlineData("/tenants/c%2fd/connect/token", "slashed-lower", "/tenants/c%2fd")]
    [InlineData("/.well-known/openid-configuration/tenants/société", "societe", "/tenants/société")]
    public async Task AnIssuerPathWithEncodedCharacters_MatchesTheDecodedRequestPath(
        string path, string tenantId, string pathBase)
    {
        var (_, seen) = await RunAsync(SharedHost, path);

        Assert.Equal(tenantId, seen?.TenantId);
        Assert.Equal(pathBase, seen?.PathBase);
    }

    /// <summary>
    /// A proxy forwarding a prefix can leave a path base ending in a slash; the issuer at that prefix is still
    /// the one the request is addressed to.
    /// </summary>
    [Theory]
    [InlineData("proxy.example.com", "/idp/", "/connect/token", "proxied", "/idp", "/connect/token")]
    [InlineData("proxy.example.com", "/idp/", "", "proxied", "/idp", "/")]
    [InlineData("proxy-root.example.com", "/", "/connect/token", "proxy-root", "", "/connect/token")]
    public async Task APathBaseEndingInASlash_StillReachesTheIssuerAtIt(
        string host, string pathBase, string path, string tenantId, string expectedPathBase, string expectedPath)
    {
        var (_, seen) = await RunAsync(host, path, pathBase: pathBase);

        Assert.Equal(new Seen(tenantId, expectedPathBase, expectedPath), seen);
    }

    /// <summary>
    /// A catalog of the host's own may match by a rule of its own; a tenant whose issuer does not name the
    /// request's host and cover its path is not the request's, and the request passes on without one rather
    /// than failing.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/tenants/acme", "/tenants")]
    [InlineData("https://other.example.org/tenants", "/tenants/connect/token")]
    [InlineData("https://other.example.org/tenants", "/.well-known/openid-configuration/tenants")]
    public async Task ATenantFromACatalogWhoseIssuerIsNotTheRequestsAddress_IsNotTaken(string issuer, string path)
    {
        var acme = new TenantDefinition { Id = "acme", Issuer = issuer };
        var catalog = new Mock<ITenantCatalog>();
        catalog
            .Setup(c => c.FindByAddressAsync(It.IsAny<string>(), It.IsAny<string>(), It.IsAny<CancellationToken>()))
            .ReturnsAsync(acme);

        Seen? seen = null;
        var middleware = new TenantResolutionMiddleware(
            context =>
            {
                seen = new Seen(
                    context.Features.Get<TenantContext>()?.Tenant.Id,
                    context.Request.PathBase.Value ?? string.Empty,
                    context.Request.Path.Value ?? string.Empty);
                return Task.CompletedTask;
            },
            catalog.Object);

        var httpContext = new DefaultHttpContext();
        httpContext.Request.Host = new HostString(SharedHost);
        httpContext.Request.Path = path;

        await middleware.InvokeAsync(httpContext);

        Assert.Equal(new Seen(null, string.Empty, path), seen);
    }

    /// <summary>
    /// The case of an encoded slash only decides the match: the path base and the path handed on keep the
    /// spelling the client sent, since the request address a client assertion's audience is checked against is
    /// built from them.
    /// </summary>
    [Fact]
    public async Task AnEncodedSlash_KeepsTheClientsSpelling_InThePathHandedOn()
    {
        var (_, seen) = await RunAsync(SharedHost, "/tenants/c%2fd/files/x%2fy");

        Assert.Equal(new Seen("slashed-lower", "/tenants/c%2fd", "/files/x%2fy"), seen);
    }

    /// <summary>
    /// A path base the host set in either case of an encoded slash is extended by the issuer's path.
    /// </summary>
    [Theory]
    [InlineData("/x%2fy")]
    [InlineData("/x%2Fy")]
    public async Task APathBaseWithAnEncodedSlash_IsExtendedByTheIssuersPath(string pathBase)
    {
        var (_, seen) = await RunAsync(MountedHost, "/mounted/connect/token", pathBase: pathBase);

        Assert.Equal(new Seen("mounted", pathBase + "/mounted", "/connect/token"), seen);
    }

    /// <summary>
    /// A request names an IPv6 host in brackets and in whatever spelling its client chose, so an address host is
    /// compared in its canonical form.
    /// </summary>
    [Theory]
    [InlineData("[::1]:5000", "/connect/token", "loopback6")]
    [InlineData("[0:0::1]", "/connect/token", "loopback6")]
    [InlineData("127.0.0.1:5000", "/tenants/local/connect/token", "loopback4")]
    [InlineData("127.1", "/tenants/local/connect/token", "loopback4")]
    public async Task AnIssuerOnAnIpAddress_MatchesAnySpellingOfThatAddress(string host, string path, string tenantId)
    {
        var (_, seen) = await RunAsync(host, path);

        Assert.Equal(tenantId, seen?.TenantId);
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
