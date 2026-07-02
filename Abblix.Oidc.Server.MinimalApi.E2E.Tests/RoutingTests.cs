// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Diagnostics.CodeAnalysis;
using System.Net;
using System.Net.Http.Json;
using System.Net.Mime;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.MinimalApi.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using EndpointResponse = Abblix.Oidc.Server.Endpoints.Configuration.Interfaces.ConfigurationResponse;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// Coverage for the adapter's routing and host-configuration surface — the parts that live in
/// <c>MapOidcEndpoints</c> rather than in the core: the optional route prefix, the per-endpoint enable flags, and the
/// HTTP-method gating each <c>MapPost</c>/<c>MapMethods</c> produces.
/// </summary>
public sealed class RoutingTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private const string RoutePrefix = "/oauth";

    private static HttpClient ClientOf(WebApplicationFactory<Program> f) => f.CreateClient(
        new WebApplicationFactoryClientOptions { AllowAutoRedirect = false, BaseAddress = TestFactory.BaseAddress });

    [Fact]
    public async Task Post_only_endpoint_rejects_get_with_405()
    {
        var client = ClientOf(factory);
        var discovery = await client.FetchDiscoveryAsync();
        var tokenPath = new Uri(discovery[ConfigurationResponse.Parameters.TokenEndpoint]!.GetValue<string>()).AbsolutePath;

        // The token endpoint is mapped POST-only; a GET matches the path but not the method, so ASP.NET routing
        // answers 405 (not 404).
        var response = await client.GetAsync(tokenPath, TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.MethodNotAllowed, response.StatusCode);
    }

    [Fact]
    public async Task Custom_prefix_mounts_all_endpoints_under_the_prefix()
    {
        using var prefixed = factory.WithWebHostBuilder(builder =>
            builder.UseSetting(MinimalApiTestConstants.RoutePrefixConfigKey, RoutePrefix));
        var client = ClientOf(prefixed);

        // MapOidcEndpoints(RoutePrefix) mounts the whole surface under the prefix.
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
        var introspectPath = new Uri(discovery[ConfigurationResponse.Parameters.IntrospectionEndpoint]!.GetValue<string>()).AbsolutePath;

        // A host that clears the Introspection flag never maps the endpoint, so the same path is a 404.
        using var disabled = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.EnabledEndpoints &= ~OidcEndpoints.Introspection))));
        var client = ClientOf(disabled);

        var response = await client.PostAsync(introspectPath, new FormUrlEncodedContent(
            new Dictionary<string, string> { [IntrospectionRequest.Parameters.Token] = "irrelevant" }), TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task Base_configuration_advertises_and_maps_no_opt_in_endpoint()
    {
        // The full host advertises introspection; capture the path it maps so we can prove the Base host 404s it.
        var introspectPath = new Uri((await ClientOf(factory).FetchDiscoveryAsync())
            [ConfigurationResponse.Parameters.IntrospectionEndpoint]!.GetValue<string>()).AbsolutePath;

        // Reset the host to the default OidcEndpoints.Base set — the state of a server that opts into nothing.
        using var baseHost = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.EnabledEndpoints = OidcEndpoints.Base))));
        var client = ClientOf(baseHost);
        var baseDiscovery = await client.FetchDiscoveryAsync();

        // A base endpoint stays advertised; every opt-in endpoint drops out of the discovery document.
        Assert.NotNull(baseDiscovery[ConfigurationResponse.Parameters.TokenEndpoint]);
        Assert.Null(baseDiscovery[ConfigurationResponse.Parameters.IntrospectionEndpoint]);
        Assert.Null(baseDiscovery[ConfigurationResponse.Parameters.RevocationEndpoint]);
        Assert.Null(baseDiscovery[ConfigurationResponse.Parameters.RegistrationEndpoint]);

        // And the path the full host mapped for introspection is unmapped here.
        var response = await client.PostAsync(introspectPath, new FormUrlEncodedContent(
            new Dictionary<string, string> { [IntrospectionRequest.Parameters.Token] = "irrelevant" }),
            TestContext.Current.CancellationToken);
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
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.AuthorizationEndpoint), new Dictionary<string, string>
            {
                [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
                [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
                [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
                [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
                [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
                [AuthorizationRequest.Parameters.Prompt] = "bogus",
            }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(MediaTypeNames.Application.Json, response.Content.Headers.ContentType?.MediaType);
        var body = JsonNode.Parse(
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        Assert.Equal(ErrorCodes.InvalidRequest, body[ResponseParameters.Error]!.GetValue<string>());
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
        Assert.Null(discovery[ConfigurationResponse.Parameters.Issuer]);
    }

    [Fact]
    public async Task Discovery_document_urls_carry_the_route_prefix()
    {
        using var prefixed = factory.WithWebHostBuilder(builder =>
            builder.UseSetting(MinimalApiTestConstants.RoutePrefixConfigKey, RoutePrefix));
        var client = ClientOf(prefixed);

        // MapOidcEndpoints(RoutePrefix) mounts the token endpoint at /oauth/connect/token, so discovery must advertise
        // the prefixed URL — a bare /connect/token would 404 every discovery-driven client.
        var discovery = await client.FetchDiscoveryAsync(RoutePrefix);

        foreach (var key in new[]
                 {
                     ConfigurationResponse.Parameters.TokenEndpoint,
                     ConfigurationResponse.Parameters.AuthorizationEndpoint,
                     ConfigurationResponse.Parameters.UserInfoEndpoint,
                     ConfigurationResponse.Parameters.JwksUri,
                     ConfigurationResponse.Parameters.RegistrationEndpoint,
                 })
        {
            var url = discovery[key]!.GetValue<string>();
            Assert.StartsWith("/oauth/", new Uri(url).AbsolutePath);
        }
    }

    [Fact]
    public async Task Registration_client_uri_carries_the_route_prefix()
    {
        using var prefixed = factory.WithWebHostBuilder(builder =>
            builder.UseSetting(MinimalApiTestConstants.RoutePrefixConfigKey, RoutePrefix));
        var client = ClientOf(prefixed);

        // Post directly to the known prefixed path (before the #10 fix the discovery registration_endpoint is wrong,
        // so we cannot rely on it to find the endpoint). Open DCR: no initial access token needed.
        var response = await client.PostAsync("/oauth/connect/register", JsonContent.Create(new JsonObject
        {
            [ClientRegistrationRequest.Parameters.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [ClientRegistrationRequest.Parameters.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
            [ClientRegistrationRequest.Parameters.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [ClientRegistrationRequest.Parameters.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretBasic,
            [ClientRegistrationRequest.Parameters.ClientName] = "Prefix Test Client",
        }), TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
        var body = JsonNode.Parse(
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
        var registrationClientUri = body["registration_client_uri"]!.GetValue<string>();

        Assert.StartsWith("/oauth/connect/register/", new Uri(registrationClientUri).AbsolutePath);
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    public async Task Discovery_and_jwks_are_cors_enabled_like_the_mvc_discovery_controller(string path)
    {
        using var corsHost = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddCors(options => options.AddPolicy(
                    OidcConstants.CorsPolicyName,
                    policy => policy.AllowAnyOrigin().AllowAnyHeader().AllowAnyMethod()))));
        var client = ClientOf(corsHost);

        using var request = new HttpRequestMessage(HttpMethod.Get, path);
        request.Headers.Add("Origin", "https://spa.example.com");
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.True(response.Headers.Contains("Access-Control-Allow-Origin"),
            $"{path} returned no Access-Control-Allow-Origin; browser RPs cannot read it cross-origin.");
    }

    [Theory]
    [InlineData("/.well-known/openid-configuration")]
    [InlineData("/.well-known/jwks")]
    public async Task Every_oidc_response_is_no_store_like_the_mvc_controllers(string path)
    {
        var client = ClientOf(factory);
        var response = await client.GetAsync(path, TestContext.Current.CancellationToken);
        response.EnsureSuccessStatusCode();

        Assert.NotNull(response.Headers.CacheControl);
        Assert.True(response.Headers.CacheControl!.NoStore,
            $"{path} response is not Cache-Control: no-store; a shared cache may store it.");
    }

    [Fact]
    public async Task Post_authorize_prefers_form_over_query_on_a_duplicate_parameter()
    {
        var client = ClientOf(factory);
        var discovery = await client.FetchDiscoveryAsync();
        var (_, challenge) = OidcFlows.Pkce();
        const string formState = "STATE_FROM_FORM";
        const string queryState = "STATE_FROM_QUERY";

        var authorizeEndpoint = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.AuthorizationEndpoint);
        var url = OidcFlows.BuildQuery(authorizeEndpoint, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.State] = queryState,
        });

        var form = new Dictionary<string, string>
        {
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            [AuthorizationRequest.Parameters.State] = formState,
        };

        var response = await client.PostAsync(url, new FormUrlEncodedContent(form), TestContext.Current.CancellationToken);

        Assert.True(response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found,
            $"/authorize returned {(int)response.StatusCode}, expected a redirect");
        var echoedState = System.Web.HttpUtility.ParseQueryString(response.Headers.Location!.Query)["state"];
        Assert.Equal(formState, echoedState);
    }

    [Fact]
    [SuppressMessage("Minor Code Smell", "S1075", Justification = "In-memory TestServer http base address; not a deployment URL.")]
    public async Task Non_https_token_request_is_refused()
    {
        var httpClient = factory.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = new Uri("http://localhost"),
        });

        // Over http the group's HTTPS filter refuses a credential-carrying POST rather than serving it in cleartext,
        // mirroring the MVC controllers' [RequireHttps]. TestServer honours the request scheme, so Request.IsHttps is
        // false here.
        var response = await httpClient.PostAsync("/connect/token", new FormUrlEncodedContent(
            new Dictionary<string, string> { [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials }),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Forbidden, response.StatusCode);
    }

    /// <summary>A stand-in discovery formatter a host registers to prove its registration wins over the adapter's.</summary>
    private sealed class MarkerConfigurationFormatter : IConfigurationResultFormatter
    {
        public Task<IResult> FormatResponseAsync(EndpointResponse response)
            => Task.FromResult(Results.Json(new Dictionary<string, object> { ["host_override_marker"] = true }));
    }
}
