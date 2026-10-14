// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

#if !MINIMAL_API_TRANSPORT
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using System.Security.Cryptography.X509Certificates;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Mvc;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.ApiExplorer;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.AspNetCore.OpenApi;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Net.Http.Headers;
using Microsoft.OpenApi;
using Swashbuckle.AspNetCore.Swagger;
using Xunit;

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

    /// <summary>
    /// The OpenAPI generator most hosts run builds the whole document with the library's endpoints in it. A
    /// generator keys the fields of a form by name, so a field described twice stops it building anything.
    /// </summary>
    [Fact]
    public async Task SwashbuckleBuildsTheDocumentWithTheLibrarysEndpoints()
    {
        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.AddSwaggerGen(options => options.SwaggerDoc(Document, new OpenApiInfo()))));

        var document = host.Services.GetRequiredService<ISwaggerProvider>().GetSwagger(Document);

        Assert.Contains("/connect/token", document.Paths.Keys);
        AssertThePushedRequestIsDescribedAsSent(
            await document.SerializeAsJsonAsync(OpenApiSpecVersion.OpenApi3_0, TestContext.Current.CancellationToken));
    }

    /// <summary>The OpenAPI generator ASP.NET Core ships builds the document with the library's endpoints in it.</summary>
    [Fact]
    public async Task TheAspNetCoreGeneratorBuildsTheDocumentWithTheLibrarysEndpoints()
    {
        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.AddOpenApi(Document)));

        var document = await host.Services.GetRequiredKeyedService<IOpenApiDocumentProvider>(Document)
            .GetOpenApiDocumentAsync(TestContext.Current.CancellationToken);

        Assert.Contains("/connect/token", document.Paths.Keys);
        AssertThePushedRequestIsDescribedAsSent(
            await document.SerializeAsJsonAsync(OpenApiSpecVersion.OpenApi3_0, TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// A field the library reads through a binder of its own is described as the string the request carries: the
    /// claims request as one JSON field, the maximum authentication age in seconds, the scope space-separated.
    /// </summary>
    [Theory]
    [InlineData(AuthorizationRequest.Parameters.Claims)]
    [InlineData(AuthorizationRequest.Parameters.MaxAge)]
    [InlineData(AuthorizationRequest.Parameters.Scope)]
    public void AFieldIsDescribedAsTheStringTheRequestCarries(string field)
    {
        var par = Single(Descriptions(Factory.Services), "POST", "connect/par");

        var parameter = Assert.Single(par.ParameterDescriptions, parameter => parameter.Name == field);
        Assert.Equal(typeof(string), parameter.Type);
        Assert.Equal(BindingSource.Form, parameter.Source);
        Assert.DoesNotContain(par.ParameterDescriptions, parameter => parameter.Name.StartsWith(field + ".", StringComparison.Ordinal));
    }

    /// <summary>The client's certificate comes from the connection, so no description asks the request for it.</summary>
    [Fact]
    public void TheClientCertificateIsNoParameter()
        => Assert.All(Descriptions(Factory.Services).Where(IsLibrarys), description =>
            Assert.DoesNotContain(description.ParameterDescriptions, parameter => parameter.Source == BindingSource.Custom));

    [Fact]
    public void NoLibraryDescriptionNamesAParameterTwiceFromOneSource()
        => Assert.All(Descriptions(Factory.Services).Where(IsLibrarys), description =>
            Assert.Equal(
                description.ParameterDescriptions.Count,
                description.ParameterDescriptions.DistinctBy(parameter => (parameter.Name, parameter.Source?.Id)).Count()));

    [Fact]
    public async Task ExcludingTheMappingFromTheDescriptionRemovesTheLibrarysEndpoints()
    {
        await using var app = await StartAsync(mapping => mapping.ExcludeFromDescription());

        Assert.DoesNotContain(Descriptions(app.Services), IsLibrarys);
    }

    [Fact]
    public async Task AGroupNameOnTheMappingGroupsTheLibrarysEndpoints()
    {
        await using var app = await StartAsync(mapping => mapping.WithGroupName(Group));

        var library = Descriptions(app.Services).Where(IsLibrarys).ToList();
        Assert.NotEmpty(library);
        Assert.All(library, description => Assert.Equal(Group, description.GroupName));
    }

    /// <summary>
    /// The form of the pushed authorization request in a built document carries each field as the request does: the
    /// claims request, the maximum authentication age and the scope as strings, nothing named after a member of the
    /// types they are read into, and no client certificate.
    /// </summary>
    private static void AssertThePushedRequestIsDescribedAsSent(string json)
    {
        var document = JsonNode.Parse(json)!;
        var content = document["paths"]!["/connect/par"]!["post"]!["requestBody"]!["content"]!.AsObject();
        var schema = Assert.Single(content).Value!["schema"]!;

        // Swashbuckle lists a form's fields under one object; the platform's generator gives each field an object of
        // its own under allOf.
        var fields = new[] { schema }
            .Concat(schema["allOf"]?.AsArray() ?? [])
            .SelectMany(part => part!["properties"]?.AsObject() ?? [])
            .ToDictionary(field => field.Key, field => field.Value);

        foreach (var field in new[]
                 {
                     AuthorizationRequest.Parameters.Claims,
                     AuthorizationRequest.Parameters.MaxAge,
                     AuthorizationRequest.Parameters.Scope,
                 })
        {
            Assert.Equal("string", fields.GetValueOrDefault(field)?["type"]?.GetValue<string>());
        }

        Assert.DoesNotContain(fields, field => field.Key.Contains('.'));
        Assert.DoesNotContain(nameof(X509Certificate2), json);
    }

    private const string Document = "v1";
    private const string Group = "oidc";

    private static bool IsLibrarys(ApiDescription description)
        => description.ActionDescriptor is ControllerActionDescriptor action &&
           action.ControllerTypeInfo.Assembly == typeof(Abblix.Oidc.Server.Mvc.Controllers.TokenController).Assembly;

    /// <summary>A host of its own, so a convention can be applied to what the mapping call returns.</summary>
    private static async Task<WebApplication> StartAsync(Action<IEndpointConventionBuilder> convention)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddOidcServices(options =>
        {
            options.Issuer = TestConstants.IssuerUri;
            options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)];
        });

        var app = builder.Build();
        convention(app.MapOidcControllers());
        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
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
