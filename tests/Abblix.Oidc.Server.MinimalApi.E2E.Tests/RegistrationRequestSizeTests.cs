// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// The bound on the registration body, which is the only bound that runs early enough to matter: model binding
/// materializes the members this server does not model ahead of every validator, so an oversized body is paid
/// for before anything in the pipeline has an opinion about it.
/// </summary>
public sealed class RegistrationRequestSizeTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private HttpClient CreateClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        BaseAddress = TestFactory.BaseAddress,
    });

    /// <summary>
    /// Both endpoints that bind a registration document carry the configured limit as metadata, which is
    /// where the server reads it - before the endpoint's own delegate runs, and therefore before the body
    /// is bound.
    /// </summary>
    /// <remarks>
    /// Asserted as metadata rather than as a refused request because enforcement belongs to the server, and
    /// the in-memory test server does not implement <c>IHttpMaxRequestBodySizeFeature</c> at all - a request
    /// over the limit sails through it, so a test asserting a 413 here would be a check that cannot fail.
    /// What can go wrong is the wiring: an endpoint mapped without the metadata is unbounded and looks
    /// exactly like a bounded one from the outside, which is how the update endpoint was left open while
    /// registration beside it was closed.
    /// <para>
    /// The routes are read from <see cref="OidcRouteOptions"/> rather than written out, because a host may
    /// move them and this suite would then look for an endpoint nobody mapped - which surfaces as an
    /// unrelated-looking crash rather than as an unbounded endpoint.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    public void Every_endpoint_binding_a_registration_carries_the_configured_body_limit(string method)
    {
        var services = factory.Services;
        var configured = services.GetRequiredService<IOptions<OidcOptions>>().Value.MaxRegistrationRequestSize;
        var routes = services.GetRequiredService<IOptions<OidcRouteOptions>>().Value;
        var route = method is "POST" ? routes.Register : routes.RegisterClient;

        var endpoint = services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Single(candidate =>
                candidate.RoutePattern.RawText == route
                && candidate.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods.Contains(method));

        var limit = endpoint.Metadata.GetMetadata<IRequestSizeLimitMetadata>();

        Assert.NotNull(limit);
        Assert.Equal(configured, limit.MaxRequestBodySize);
    }

    /// <summary>
    /// A cleared limit attaches no metadata at all, rather than metadata carrying a cleared value.
    /// </summary>
    /// <remarks>
    /// The distinction is the whole of it, and it runs the opposite way to how it reads. The routing
    /// middleware writes whatever the metadata says onto <c>IHttpMaxRequestBodySizeFeature</c>, where a
    /// cleared value means unlimited - it is the value <c>DisableRequestSizeLimitAttribute</c> is built on.
    /// So attaching it would remove the server's own default on the one endpoint that most needs a bound,
    /// while reading in configuration as the most cautious setting available. Measured on Kestrel while
    /// writing this: an endpoint with no metadata refuses a 40 MB body with 413, and the same endpoint
    /// carrying null-valued metadata accepts it and reads every byte.
    /// </remarks>
    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    public async Task A_cleared_limit_attaches_no_metadata(string method)
    {
        await using var host = factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.Configure<OidcOptions>(options => options.MaxRegistrationRequestSize = null)));

        var services = host.Services;
        var routes = services.GetRequiredService<IOptions<OidcRouteOptions>>().Value;
        var route = method is "POST" ? routes.Register : routes.RegisterClient;

        var endpoint = services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Single(candidate =>
                candidate.RoutePattern.RawText == route
                && candidate.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods.Contains(method));

        Assert.Null(endpoint.Metadata.GetMetadata<IRequestSizeLimitMetadata>());
    }

    /// <summary>
    /// A registration within the limit still goes through. The bound is generous next to a real registration,
    /// and a limit that refuses ordinary traffic would be found by hosts rather than by this suite.
    /// </summary>
    [Fact]
    public async Task A_registration_within_the_limit_is_accepted()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        var response = await client.PostAsync(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.RegistrationEndpoint),
            JsonContent.Create(new JsonObject
            {
                [ClientRegistrationRequest.Parameters.ClientName] = $"within-the-limit-{Guid.NewGuid():N}",
                [ClientRegistrationRequest.Parameters.RedirectUris] =
                    new JsonArray { "https://client.example.com/callback" },
                ["x_vendor_note"] = new string('a', 1024),
            }),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }
}
