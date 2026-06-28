// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.MinimalApi.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using EndpointResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// Coverage for the adapter's routing and host-configuration surface — the parts that live in
/// <c>MapOidcEndpoints</c> rather than in the core: the optional route prefix, the per-endpoint enable flags, and the
/// HTTP-method gating each <c>MapPost</c>/<c>MapMethods</c> produces.
/// </summary>
public sealed class RoutingTests(TestFactory factory) : IClassFixture<TestFactory>
{
    [SuppressMessage("Minor Code Smell", "S1075", Justification = "In-memory TestServer base address; not a deployment URL.")]
    private static readonly Uri Base = new("https://localhost");

    private static HttpClient ClientOf(WebApplicationFactory<Program> f) => f.CreateClient(
        new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = Base });

    [Fact]
    public async Task Post_only_endpoint_rejects_get_with_405()
    {
        var client = ClientOf(factory);
        var discovery = await client.FetchDiscoveryAsync();
        var tokenPath = new Uri(discovery["token_endpoint"]!.GetValue<string>()).AbsolutePath;

        // The token endpoint is mapped POST-only; a GET matches the path but not the method, so ASP.NET routing
        // answers 405 (not 404).
        var response = await client.GetAsync(tokenPath, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    [Fact]
    public async Task Custom_prefix_mounts_all_endpoints_under_the_prefix()
    {
        using var prefixed = factory.WithWebHostBuilder(builder =>
            builder.UseSetting(MinimalApiTestConstants.RoutePrefixConfigKey, "/oauth"));
        var client = ClientOf(prefixed);

        // MapOidcEndpoints("/oauth") mounts the whole surface under the prefix.
        var underPrefix = await client.GetAsync("/oauth/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.OK, underPrefix.StatusCode);

        // The bare path is no longer mapped.
        var bare = await client.GetAsync("/.well-known/openid-configuration", TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, bare.StatusCode);
    }

    [Fact]
    public async Task Disabled_endpoint_is_not_mapped_and_returns_404()
    {
        // The introspection path as the enabled host maps it.
        var enabledClient = ClientOf(factory);
        var discovery = await enabledClient.FetchDiscoveryAsync();
        var introspectPath = new Uri(discovery["introspection_endpoint"]!.GetValue<string>()).AbsolutePath;

        // A host that clears the Introspection flag never maps the endpoint, so the same path is a 404.
        using var disabled = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.EnabledEndpoints &= ~OidcEndpoints.Introspection))));
        var client = ClientOf(disabled);

        var response = await client.PostAsync(introspectPath, new FormUrlEncodedContent(
            new Dictionary<string, string> { ["token"] = "irrelevant" }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Model_validation_failure_is_rendered_as_oauth_invalid_request_json()
    {
        var client = ClientOf(factory);
        var discovery = await client.FetchDiscoveryAsync();
        var (_, challenge) = OidcFlows.Pkce();

        // prompt has a spec-fixed value set; "bogus" is not one of them. The OAuth-shaped contract (matching the
        // MVC adapter) is a 400 with {"error":"invalid_request"} served as application/json — not the framework
        // default ValidationProblemDetails (application/problem+json), which omits the error code OIDC clients read.
        var response = await client.GetAsync(OidcFlows.BuildQuery(
            OidcFlows.Endpoint(discovery, "authorization_endpoint"), new Dictionary<string, string>
            {
                ["client_id"] = TestConstants.ConfidentialClientId,
                ["response_type"] = ResponseTypes.Code,
                ["redirect_uri"] = TestConstants.RedirectUri,
                ["scope"] = Scopes.OpenId,
                ["code_challenge"] = challenge,
                ["code_challenge_method"] = CodeChallengeMethods.S256,
                ["prompt"] = "bogus",
            }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal("application/json", response.Content.Headers.ContentType?.MediaType);
        var body = JsonNode.Parse(
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidRequest, body["error"]!.GetValue<string>());
    }

    [Fact]
    public async Task Host_registered_formatter_overrides_the_adapter_default()
    {
        // The adapter registers every formatter via TryAdd, so a host that registers its own implementation is used
        // instead of the default — this is the host-extensibility contract the adapter promises.
        using var overridden = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddScoped<IConfigurationResultFormatter, MarkerConfigurationFormatter>()));
        var client = ClientOf(overridden);

        var discovery = JsonNode.Parse(await client.GetStringAsync(
            "/.well-known/openid-configuration", TestContext.Current.CancellationToken))!.AsObject();

        // The discovery document is the host formatter's marker object, not the adapter's metadata.
        Assert.True(discovery["host_override_marker"]?.GetValue<bool>());
        Assert.Null(discovery["issuer"]);
    }

    /// <summary>A stand-in discovery formatter a host registers to prove its registration wins over the adapter's.</summary>
    private sealed class MarkerConfigurationFormatter : IConfigurationResultFormatter
    {
        public Task<IResult> FormatResponseAsync(EndpointResponse response)
            => Task.FromResult(Results.Json(new Dictionary<string, object> { ["host_override_marker"] = true }));
    }
}
