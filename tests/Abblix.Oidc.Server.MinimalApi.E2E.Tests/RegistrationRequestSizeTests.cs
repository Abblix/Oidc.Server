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
    /// The endpoint carries the configured limit as metadata, which is where the server reads it - before the
    /// endpoint's own delegate runs, and therefore before the body is bound.
    /// </summary>
    /// <remarks>
    /// Asserted as metadata rather than as a refused request because enforcement belongs to the server, and the
    /// in-memory test server does not enforce it. What can go wrong here is the wiring: an endpoint mapped
    /// without the metadata is unbounded, and looks exactly like a bounded one from the outside.
    /// </remarks>
    [Fact]
    public void The_registration_endpoint_carries_the_configured_body_limit()
    {
        var services = factory.Services;
        var configured = services.GetRequiredService<IOptions<OidcOptions>>().Value.MaxRegistrationRequestSize;

        var registration = services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Single(endpoint =>
                endpoint.RoutePattern.RawText is "/connect/register"
                && endpoint.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods.Contains(HttpMethods.Post));

        var limit = registration.Metadata.GetMetadata<IRequestSizeLimitMetadata>();

        Assert.NotNull(limit);
        Assert.Equal(configured, limit.MaxRequestBodySize);
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
