// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// An endpoint the host has not enabled answers 404 at the path it would have, on either host.
/// </summary>
public class DisabledEndpointTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task ADisabledEndpointAnswers404()
    {
        var discovery = await FetchDiscoveryAsync(CreateClient());
        Assert.NotNull(discovery.IntrospectionEndpoint);

        await using var disabled = Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.EnabledEndpoints &= ~OidcEndpoints.Introspection))));
        using var client = disabled.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

        using var response = await client.PostAsync(
            discovery.IntrospectionEndpoint.AbsolutePath,
            new FormUrlEncodedContent(new Dictionary<string, string> { [IntrospectionRequest.Parameters.Token] = "any" }),
            TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }
}
