// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Xunit;

#if !MINIMAL_API_TRANSPORT
namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The host's API description lists the endpoints the library mapped, with their parameters and where each comes
/// from, as it lists an action of the host's own.
/// </summary>
public class ApiDescriptionTests(TestFactory factory) : TestBase(factory)
{
    private static IReadOnlyList<ApiDescription> Descriptions(IServiceProvider services)
        => services.GetRequiredService<IApiDescriptionGroupCollectionProvider>()
            .ApiDescriptionGroups.Items
            .SelectMany(group => group.Items)
            .ToList();

    private static ApiDescription Single(IReadOnlyList<ApiDescription> descriptions, string method, string path)
        => Assert.Single(descriptions, description =>
            description.HttpMethod == method && description.RelativePath == path);

    [Fact]
    public void ATokenRequestIsDescribedWithItsFormFields()
    {
        var token = Single(Descriptions(Factory.Services), "POST", "connect/token");

        Assert.Contains(token.ParameterDescriptions, parameter =>
            parameter.Name == TokenRequest.Parameters.GrantType && parameter.Source == BindingSource.Form);
        Assert.Contains(token.ParameterDescriptions, parameter =>
            parameter.Name == TokenRequest.Parameters.Code && parameter.Source == BindingSource.Form);
        Assert.Contains(token.ParameterDescriptions, parameter =>
            parameter.Name == HeaderNames.Authorization && parameter.Source == BindingSource.Header);
    }

    [Fact]
    public void AClientConfigurationRequestIsDescribedWithItsRouteParameter()
    {
        var read = Single(Descriptions(Factory.Services), "GET", "connect/register/{clientId}");

        Assert.Contains(read.ParameterDescriptions, parameter =>
            parameter.Name == "clientId" && parameter.Source == BindingSource.Path);
    }

    [Fact]
    public void TheDiscoveryDocumentIsDescribed()
        => Single(Descriptions(Factory.Services), "GET", ".well-known/openid-configuration");

    [Fact]
    public async Task ADisabledEndpointIsNotDescribed()
    {
        Single(Descriptions(Factory.Services), "POST", "connect/introspect");

        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ => new PostConfigureOptions<OidcOptions>(
                Options.DefaultName,
                options => options.EnabledEndpoints &= ~OidcEndpoints.Introspection))));

        Assert.DoesNotContain(Descriptions(host.Services), description =>
            description.RelativePath == "connect/introspect");
    }

    [Fact]
    public async Task APrefixIsInTheDescribedPath()
    {
        await using var host = Factory.WithWebHostBuilder(builder =>
            builder.UseSetting(TestConstants.RoutePrefixConfigKey, "/oauth"));

        Single(Descriptions(host.Services), "POST", "oauth/connect/token");
    }
}
#endif
