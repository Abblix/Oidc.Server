// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Diagnostics.CodeAnalysis;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.MinimalApi.Features.EndpointResolving;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;

namespace Abblix.Oidc.Server.MinimalApi.UnitTests;

/// <summary>
/// What the Minimal API adapter answers for <c>IOidcEndpointResolver</c>, the contract the MVC adapter answers
/// too so that host code needing an OIDC endpoint's URL survives a change of adapter.
/// </summary>
/// <remarks>
/// The twin of the MVC suite's file of the same name, asserting the same behaviours through the other
/// mechanism. Where MVC resolves a tokenized route template, this side asks <see cref="LinkGenerator"/> for the
/// endpoint the route was mapped under - which is why the name it asks for is what these tests pin. A wrong
/// name does not fail loudly; it returns null, or worse, another endpoint's address.
/// </remarks>
public class OidcEndpointResolverTests
{
    /// <summary>
    /// Records the endpoint name asked for and answers with a URL derived from it, so a test can tell both
    /// that the resolver asked and what it asked for.
    /// </summary>
    private sealed class RecordingLinkGenerator : LinkGenerator
    {
        public string? RequestedName { get; private set; }

        public override string? GetUriByAddress<TAddress>(
            HttpContext httpContext, TAddress address, RouteValueDictionary values,
            RouteValueDictionary? ambientValues = null, string? scheme = null, HostString? host = null,
            PathString? pathBase = null, FragmentString fragment = new(),
            LinkOptions? options = null)
        {
            RequestedName = address as string;
            return $"https://example.com/resolved/{RequestedName}";
        }

        public override string? GetUriByAddress<TAddress>(
            TAddress address, RouteValueDictionary values, string? scheme, HostString host,
            PathString pathBase = new(), FragmentString fragment = new(), LinkOptions? options = null)
            => throw new NotSupportedException("The resolver builds URLs from the current request.");

        [SuppressMessage("Major Code Smell", "S4144:Methods should not have identical implementations",
            Justification = "Two distinct LinkGenerator overloads; the resolver uses neither path-only form.")]
        public override string? GetPathByAddress<TAddress>(
            HttpContext httpContext, TAddress address, RouteValueDictionary values,
            RouteValueDictionary? ambientValues = null, PathString? pathBase = null,
            FragmentString fragment = new(), LinkOptions? options = null)
            => throw new NotSupportedException("The resolver builds absolute URLs.");

        public override string? GetPathByAddress<TAddress>(
            TAddress address, RouteValueDictionary values, PathString pathBase = new(),
            FragmentString fragment = new(), LinkOptions? options = null)
            => throw new NotSupportedException("The resolver builds absolute URLs.");
    }

    private static (OidcEndpointResolver Resolver, RecordingLinkGenerator Links) Create(
        bool withRequest = true)
    {
        var accessor = new HttpContextAccessor
        {
            HttpContext = withRequest ? new DefaultHttpContext() : null,
        };

        var links = new RecordingLinkGenerator();
        return (new OidcEndpointResolver(accessor, links), links);
    }

    /// <summary>
    /// Every endpoint asks for the name its route was mapped under. Driving the whole set is what catches a
    /// mis-keyed entry in the endpoint-to-name table, which would otherwise surface as the adapter quietly
    /// handing out another endpoint's address - or nothing at all.
    /// </summary>
    [Theory]
    [InlineData(OidcEndpoints.Authorize, "Abblix.Oidc.Authorize")]
    [InlineData(OidcEndpoints.Token, "Abblix.Oidc.Token")]
    [InlineData(OidcEndpoints.UserInfo, "Abblix.Oidc.UserInfo")]
    [InlineData(OidcEndpoints.EndSession, "Abblix.Oidc.EndSession")]
    [InlineData(OidcEndpoints.CheckSession, "Abblix.Oidc.CheckSession")]
    [InlineData(OidcEndpoints.Revocation, "Abblix.Oidc.Revocation")]
    [InlineData(OidcEndpoints.Introspection, "Abblix.Oidc.Introspection")]
    [InlineData(OidcEndpoints.PushedAuthorizationRequest, "Abblix.Oidc.PushedAuthorizationRequest")]
    [InlineData(OidcEndpoints.BackChannelAuthentication, "Abblix.Oidc.BackChannelAuthentication")]
    [InlineData(OidcEndpoints.DeviceAuthorization, "Abblix.Oidc.DeviceAuthorization")]
    [InlineData(OidcEndpoints.RegisterClient, "Abblix.Oidc.Register")]
    [InlineData(OidcEndpoints.Configuration, "Abblix.Oidc.Configuration")]
    [InlineData(OidcEndpoints.Keys, "Abblix.Oidc.Keys")]
    public void An_endpoint_is_resolved_by_the_name_its_route_was_mapped_under(
        OidcEndpoints endpoint, string expectedName)
    {
        var (resolver, links) = Create();

        var resolved = resolver.Resolve(endpoint);

        Assert.Equal(expectedName, links.RequestedName);
        Assert.Equal($"https://example.com/resolved/{expectedName}", resolved?.ToString());
    }

    /// <summary>
    /// A flag combination names a set of endpoints rather than one, so there is no URL to give back - and no
    /// question to put to the link generator either. Answering with some member of the set would be worse than
    /// answering nothing: the caller would send users at an endpoint it never asked for.
    /// </summary>
    [Theory]
    [InlineData(OidcEndpoints.All)]
    [InlineData(OidcEndpoints.Base)]
    public void A_set_of_endpoints_resolves_to_nothing(OidcEndpoints endpoints)
    {
        var (resolver, links) = Create();

        Assert.Null(resolver.Resolve(endpoints));
        Assert.Null(links.RequestedName);
    }

    /// <summary>
    /// The URL is built against the current request, so outside one there is nothing to build it from. Making
    /// something up - a configured issuer, say - would hand back an address that does not match where the
    /// caller actually is.
    /// </summary>
    [Fact]
    public void Outside_a_request_nothing_resolves()
    {
        var (resolver, links) = Create(withRequest: false);

        Assert.Null(resolver.Resolve(OidcEndpoints.Authorize));
        Assert.Null(links.RequestedName);
    }
}
