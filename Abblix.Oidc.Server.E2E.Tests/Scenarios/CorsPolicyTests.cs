// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end guard that the MVC adapter registers the CORS policy its controllers reference with
/// <c>[EnableCors]</c>, and that the host keeps full control of it — the same supplement/override contract the
/// Minimal API adapter offers, so a host that composes both adapters sees one coherent policy.
/// </summary>
public class CorsPolicyTests(TestFactory factory) : TestBase(factory)
{
    private static HttpClient ClientOf(WebApplicationFactory<Program> f) => f.CreateClient(
        new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = TestServerAddress.BaseAddress });

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/oauth-authorization-server")]
    [InlineData("/.well-known/jwks")]
    public async Task Discovery_and_jwks_are_cors_enabled_by_the_adapter_default(string path)
    {
        // No host CORS configuration: AddOidcServices already registers the policy the DiscoveryController carries,
        // so a browser RP reads the metadata cross-origin out of the box. The default allows any origin, so the
        // response reflects "*".
        var client = CreateClient();

        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("Origin", "https://spa.example.com");
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal("*", response.Headers.GetValues("Access-Control-Allow-Origin").Single());
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    public async Task Host_cors_policy_overrides_the_adapter_default(string path)
    {
        // A host that registers its own policy of the same name wins over the adapter default in any order.
        // Narrowing to one origin proves the replacement: the allowed origin is reflected, a different one is
        // refused, so the AllowAnyOrigin default is gone.
        const string allowedOrigin = "https://trusted.example.com";
        using var overridden = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddCors(options => options.AddPolicy(
                    OidcConstants.CorsPolicyName,
                    policy => policy.WithOrigins(allowedOrigin).AllowAnyHeader().AllowAnyMethod()))));
        var client = ClientOf(overridden);

        using var allowed = new HttpRequestMessage(HttpMethod.Get, path);
        allowed.Headers.Add("Origin", allowedOrigin);
        var allowedResponse = await client.SendAsync(allowed, TestContext.Current.CancellationToken);
        Assert.Equal(allowedOrigin, allowedResponse.Headers.GetValues("Access-Control-Allow-Origin").Single());

        using var refused = new HttpRequestMessage(HttpMethod.Get, path);
        refused.Headers.Add("Origin", "https://evil.example.com");
        var refusedResponse = await client.SendAsync(refused, TestContext.Current.CancellationToken);
        Assert.False(refusedResponse.Headers.Contains("Access-Control-Allow-Origin"));
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    public async Task Configured_allowed_origins_narrow_the_adapter_default(string path)
    {
        // A host that only wants to narrow origins configures OidcCorsOptions instead of redefining the whole
        // policy; the adapter builds its default from those origins. The configured origin is reflected, an
        // unconfigured one is refused.
        const string allowedOrigin = "https://spa.example.com";
        using var configured = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Configure<OidcCorsOptions>(options => options.AllowedOrigins.Add(allowedOrigin))));
        var client = ClientOf(configured);

        using var allowed = new HttpRequestMessage(HttpMethod.Get, path);
        allowed.Headers.Add("Origin", allowedOrigin);
        var allowedResponse = await client.SendAsync(allowed, TestContext.Current.CancellationToken);
        Assert.Equal(allowedOrigin, allowedResponse.Headers.GetValues("Access-Control-Allow-Origin").Single());

        using var refused = new HttpRequestMessage(HttpMethod.Get, path);
        refused.Headers.Add("Origin", "https://other.example.com");
        var refusedResponse = await client.SendAsync(refused, TestContext.Current.CancellationToken);
        Assert.False(refusedResponse.Headers.Contains("Access-Control-Allow-Origin"));
    }
}
