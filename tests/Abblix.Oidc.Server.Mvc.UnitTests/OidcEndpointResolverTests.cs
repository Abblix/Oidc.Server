// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;
using Abblix.Oidc.Server.Mvc.Features.EndpointResolving;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

/// <summary>
/// What the MVC adapter answers for <c>IOidcEndpointResolver</c>, the contract the Minimal API adapter answers
/// too so that host code needing an OIDC endpoint's URL survives a change of adapter.
/// </summary>
/// <remarks>
/// The thing worth pinning here is that a caller gets a <b>path</b>, never the tokenized template the
/// controllers carry. The resolver hands <c>Path.Authorize</c> - literally
/// <c>[route:authorize?[route:base?~/connect]/authorize]</c> - to <see cref="IUriResolver.Content"/>, and only
/// that method's own use of <see cref="ConfigurableRouteConvention"/> turns it into <c>/connect/authorize</c>.
/// Nothing in the resolver says so, so a future change to <c>Content</c> would leak template syntax into a
/// redirect URI with no test to stop it. That is what the assertions on the resolved text are for.
/// </remarks>
public class OidcEndpointResolverTests
{
    private const string ApplicationBase = "https://example.com/app";

    private static OidcEndpointResolver CreateResolver(
        OidcEndpoints enabledEndpoints = OidcEndpoints.All,
        IConfigurationSection? routes = null)
    {
        var httpContext = new DefaultHttpContext
        {
            Request = { Scheme = "https", Host = new HostString("example.com"), PathBase = "/app" },
        };

        var services = new ServiceCollection();
        services.Configure<MvcOptions>(options =>
        {
            if (routes != null)
                options.Conventions.Add(new ConfigurableRouteConvention(Path.RoutePrefix, routes));
        });
        httpContext.RequestServices = services.BuildServiceProvider();

        var accessor = new Mock<IHttpContextAccessor>(MockBehavior.Strict);
        accessor.Setup(a => a.HttpContext).Returns(httpContext);

        var uriResolver = new UriResolver(
            accessor.Object,
            new Mock<IUrlHelperFactory>(MockBehavior.Strict).Object,
            httpContext.RequestServices.GetRequiredService<IOptions<MvcOptions>>());

        return new OidcEndpointResolver(
            uriResolver,
            Options.Create(new OidcOptions { EnabledEndpoints = enabledEndpoints }));
    }

    private static IConfigurationSection Routes(params (string Token, string Value)[] entries)
        => new ConfigurationBuilder()
            .AddInMemoryCollection(entries.Select(e =>
                new KeyValuePair<string, string?>($"Routes:{e.Token}", e.Value)))
            .Build()
            .GetSection("Routes");

    /// <summary>
    /// Every endpoint resolves to the absolute URL of its default path. Driving the whole set is what catches
    /// a mis-keyed entry in the endpoint-to-template table, which would otherwise surface as the adapter
    /// quietly handing out another endpoint's address.
    /// </summary>
    [Theory]
    [InlineData(OidcEndpoints.Authorize, "/connect/authorize")]
    [InlineData(OidcEndpoints.Token, "/connect/token")]
    [InlineData(OidcEndpoints.UserInfo, "/connect/userinfo")]
    [InlineData(OidcEndpoints.EndSession, "/connect/endsession")]
    [InlineData(OidcEndpoints.CheckSession, "/connect/checksession")]
    [InlineData(OidcEndpoints.Revocation, "/connect/revoke")]
    [InlineData(OidcEndpoints.Introspection, "/connect/introspect")]
    [InlineData(OidcEndpoints.PushedAuthorizationRequest, "/connect/par")]
    [InlineData(OidcEndpoints.BackChannelAuthentication, "/connect/bc-authorize")]
    [InlineData(OidcEndpoints.DeviceAuthorization, "/connect/deviceauthorization")]
    [InlineData(OidcEndpoints.RegisterClient, "/connect/register")]
    [InlineData(OidcEndpoints.Configuration, "/.well-known/openid-configuration")]
    [InlineData(OidcEndpoints.Keys, "/.well-known/jwks")]
    public void An_endpoint_resolves_to_its_absolute_path(OidcEndpoints endpoint, string expectedPath)
        => Assert.Equal(ApplicationBase + expectedPath, CreateResolver().Resolve(endpoint)?.ToString());

    /// <summary>
    /// The route templates are tokenized, and nothing in the resolver resolves them - only what
    /// <see cref="IUriResolver.Content"/> does on its way to an absolute URL. A caller must never receive
    /// template syntax, so this asserts on its absence directly rather than trusting the path comparison
    /// above to have noticed.
    /// </summary>
    [Fact]
    public void A_resolved_url_carries_no_route_template_syntax()
    {
        var resolved = CreateResolver().Resolve(OidcEndpoints.Authorize)?.ToString();

        Assert.NotNull(resolved);
        Assert.DoesNotContain("[", resolved, StringComparison.Ordinal);
        Assert.DoesNotContain(Path.RoutePrefix + ":", resolved, StringComparison.Ordinal);
    }

    /// <summary>
    /// A host that retemplated its OIDC paths gets the paths it configured, from the same section the
    /// controllers were mapped against.
    /// </summary>
    [Fact]
    public void A_configured_route_moves_the_resolved_url()
    {
        var resolver = CreateResolver(routes: Routes(("base", "~/oauth2"), ("token", "~/oauth2/issue-token")));

        Assert.Equal($"{ApplicationBase}/oauth2/issue-token", resolver.Resolve(OidcEndpoints.Token)?.ToString());
        Assert.Equal($"{ApplicationBase}/oauth2/authorize", resolver.Resolve(OidcEndpoints.Authorize)?.ToString());
    }

    /// <summary>
    /// An endpoint the host does not serve has no URL to give back. The controller action carries its template
    /// whether or not the endpoint is enabled, so this is the one thing the MVC side has to check explicitly -
    /// on the Minimal API side a disabled endpoint was simply never mapped.
    /// </summary>
    [Fact]
    public void A_disabled_endpoint_resolves_to_nothing()
        => Assert.Null(CreateResolver(OidcEndpoints.Base).Resolve(OidcEndpoints.Introspection));

    /// <summary>
    /// A flag combination names a set of endpoints rather than one, so there is no URL to give back. Answering
    /// with some member of the set would be worse than answering nothing: the caller would send users at an
    /// endpoint it never asked for.
    /// </summary>
    [Theory]
    [InlineData(OidcEndpoints.All)]
    [InlineData(OidcEndpoints.Base)]
    public void A_set_of_endpoints_resolves_to_nothing(OidcEndpoints endpoints)
        => Assert.Null(CreateResolver().Resolve(endpoints));
}
