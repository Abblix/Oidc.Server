// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Mime;
using System.Text;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// An endpoint the host has not enabled answers 404 at the path it would have, on either host, whatever the method
/// and the media type of the request, and whether the endpoint is one action or a whole controller.
/// </summary>
public class DisabledEndpointTests(TestFactory factory) : TestBase(factory)
{
    public enum RequestShape
    {
        PostedForm,
        PostedJson,
        Get,
    }

    [Theory]
    [InlineData(RequestShape.PostedForm)]
    [InlineData(RequestShape.PostedJson)]
    [InlineData(RequestShape.Get)]
    public async Task ADisabledActionAnswers404(RequestShape shape)
    {
        var discovery = await FetchDiscoveryAsync(CreateClient());
        Assert.NotNull(discovery.IntrospectionEndpoint);

        await using var host = Factory.WithWebHostBuilder(Without(OidcEndpoints.Introspection));
        using var client = host.CreateClient(ClientOptions);
        using var request = Request(shape, discovery.IntrospectionEndpoint.AbsolutePath);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task ADisabledControllerAnswers404()
    {
        var discovery = await FetchDiscoveryAsync(CreateClient());
        Assert.NotNull(discovery.RegistrationEndpoint);

        await using var host = Factory.WithWebHostBuilder(Without(OidcEndpoints.RegisterClient));
        using var client = host.CreateClient(ClientOptions);
        using var response = await client.PostAsync(
            discovery.RegistrationEndpoint.AbsolutePath,
            new StringContent("{}", Encoding.UTF8, MediaTypeNames.Application.Json),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    private static HttpRequestMessage Request(RequestShape shape, string path) => shape switch
    {
        RequestShape.PostedForm => new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new FormUrlEncodedContent(
                new Dictionary<string, string> { [IntrospectionRequest.Parameters.Token] = "any" }),
        },
        RequestShape.PostedJson => new HttpRequestMessage(HttpMethod.Post, path)
        {
            Content = new StringContent("{}", Encoding.UTF8, MediaTypeNames.Application.Json),
        },
        RequestShape.Get => new HttpRequestMessage(HttpMethod.Get, path),
        _ => throw new ArgumentOutOfRangeException(nameof(shape), shape, null),
    };

    private static readonly WebApplicationFactoryClientOptions ClientOptions = new()
    {
        AllowAutoRedirect = false,
        BaseAddress = TestServerAddress.BaseAddress,
    };

    private static Action<IWebHostBuilder> Without(OidcEndpoints endpoint)
        => builder => builder.ConfigureTestServices(services =>
            services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                new PostConfigureOptions<OidcOptions>(
                    Options.DefaultName,
                    options => options.EnabledEndpoints &= ~endpoint)));
}
