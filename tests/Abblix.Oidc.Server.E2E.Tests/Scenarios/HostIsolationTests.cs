// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections;
using System.Globalization;
using System.Net.Mime;
using System.Reflection;
using System.Text.Json.Nodes;
using System.Text.Json.Serialization.Metadata;
using Abblix.Jwt;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Scenarios.HostIsolation;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
#if MINIMAL_API_TRANSPORT
using Abblix.Oidc.Server.MinimalApi;
#else
using Abblix.Oidc.Server.Mvc;
#endif

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The host the library is installed into notices nothing of it on its own endpoints: the same application built
/// with and without the library answers its own controller and its own Minimal API endpoint alike, and carries the
/// same application-wide MVC, JSON and routing settings.
/// </summary>
public sealed class HostIsolationTests : IAsyncLifetime
{
    private WebApplication _plain = null!;
    private WebApplication _withLibrary = null!;

    public async ValueTask InitializeAsync()
    {
        _plain = await StartAsync(withLibrary: false);
        _withLibrary = await StartAsync(withLibrary: true);
    }

    public async ValueTask DisposeAsync()
    {
        await _plain.DisposeAsync();
        await _withLibrary.DisposeAsync();
    }

    private static async Task<WebApplication> StartAsync(bool withLibrary)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddControllers();
        builder.Services.AddCors();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        if (withLibrary)
            builder.Services.AddOidcServices(options =>
            {
                // The issuer of the rest of the suite: the license counts issuers across the process
                options.Issuer = TestConstants.IssuerUri;
                options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature)];
            });

        var app = builder.Build();
        app.UseCors();
        app.MapControllers();
        app.MapGet(MinimalEchoPath, () => new HostItem { Name = HostController.Name });
        app.MapGet(HostPagePattern, (string section, string page) => new { section, page });
        if (withLibrary)
        {
#if MINIMAL_API_TRANSPORT
            IEndpointConventionBuilder mapping = app.MapOidcEndpoints();
#else
            var mapping = app.MapOidcControllers();
#endif
            mapping.WithMetadata(LibraryConvention);
            mapping.Finally(endpoint => endpoint.Metadata.Add(FinalLibraryConvention));
        }

        await app.StartAsync(TestContext.Current.CancellationToken);
        return app;
    }

    public static TheoryData<string, string, string?> Requests => new()
    {
        // A model the action declares required, posted without it: the host's own validation answer
        { HttpMethods.Post, HostController.ItemsPath, "{}" },
        // A body the host's JSON input formatter cannot read
        { HttpMethods.Post, HostController.ItemsPath, "{" },
        // A model the host serializes, a null member included
        { HttpMethods.Get, HostController.ItemsPath, null },
        // A list of cultures and a value the host binds from the query
        { HttpMethods.Get, HostController.CulturesPath + "?languages=en&languages=fr&count=2", null },
        { HttpMethods.Get, HostController.CulturesPath + "?count=two", null },
        // A plain string, which the host's own output formatters decide how to write
        { HttpMethods.Get, HostController.TextPath, null },
        // A refusal without a body, which the host's own API behavior decides how to describe
        { HttpMethods.Get, HostController.RefusedPath, null },
        // The host's own Minimal API endpoint, and a page its two-segment pattern serves
        { HttpMethods.Get, MinimalEchoPath, null },
        { HttpMethods.Get, "/docs/intro", null },
    };

    [Theory]
    [MemberData(nameof(Requests))]
    public async Task TheHostAnswersItsOwnRequestAsWithoutTheLibrary(string method, string path, string? json)
    {
        var expected = await SendAsync(_plain, method, path, json);
        var actual = await SendAsync(_withLibrary, method, path, json);

        Assert.Equal(expected.Status, actual.Status);
        Assert.Equal(expected.ContentType, actual.ContentType);
        Assert.True(JsonNode.DeepEquals(expected.Body, actual.Body), $"{expected.Body} != {actual.Body}");
    }

    /// <summary>
    /// A path of the library's stays the library's beside a host pattern that would also match it.
    /// </summary>
    [Fact]
    public async Task ALibraryPathIsServedBesideAHostPatternMatchingIt()
    {
        var (status, _, body) = await SendAsync(
            _withLibrary, HttpMethods.Get, "/.well-known/openid-configuration", null);

        Assert.Equal(StatusCodes.Status200OK, status);
        Assert.NotNull(body?[Abblix.Oidc.Server.Model.ConfigurationResponse.Parameters.Issuer]);
    }

    /// <summary>
    /// A convention the host applies through what the mapping call returns reaches the library's endpoints and none
    /// of the host's own.
    /// </summary>
    [Fact]
    public void AConventionOnTheMappingReachesTheLibrarysEndpointsAlone()
    {
        var endpoints = ((IEndpointRouteBuilder)_withLibrary).DataSources
            .SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>()
            .ToList();

        var hostEndpoints = endpoints
            .Where(endpoint => PathOf(endpoint) is var path &&
                               (path.StartsWith(HostController.ItemsPath, StringComparison.Ordinal) ||
                                path is MinimalEchoPath or HostPagePattern))
            .ToList();

        // Both kinds of the host's endpoints are in the sample, or the assertion below says nothing about one of them
        Assert.Contains(hostEndpoints, endpoint => endpoint.Metadata.GetMetadata<ControllerActionDescriptor>() != null);
        Assert.Contains(hostEndpoints, endpoint => endpoint.Metadata.GetMetadata<ControllerActionDescriptor>() == null);
        Assert.All(hostEndpoints, endpoint =>
        {
            Assert.DoesNotContain(LibraryConvention, endpoint.Metadata);
            Assert.DoesNotContain(FinalLibraryConvention, endpoint.Metadata);
        });

        // Every other endpoint of this host is the library's: more than the discovery document alone, each one
        // carrying both conventions
        var libraryEndpoints = endpoints.Except(hostEndpoints).ToList();
        Assert.Contains(libraryEndpoints, endpoint => PathOf(endpoint) == "/.well-known/openid-configuration");
        Assert.Contains(libraryEndpoints, endpoint => PathOf(endpoint) == "/connect/token");
        Assert.All(libraryEndpoints, endpoint =>
        {
            Assert.Contains(LibraryConvention, endpoint.Metadata);
            Assert.Contains(FinalLibraryConvention, endpoint.Metadata);
        });
    }

    /// <summary>
    /// The path an endpoint answers, written with its leading slash, which an attribute route template drops.
    /// </summary>
    private static string PathOf(RouteEndpoint endpoint)
        => "/" + (endpoint.RoutePattern.RawText ?? string.Empty).TrimStart('/');

    public static TheoryData<Type> ApplicationWideSettings => new()
    {
        typeof(MvcOptions),
        typeof(JsonOptions),
        typeof(Microsoft.AspNetCore.Http.Json.JsonOptions),
        typeof(ApiBehaviorOptions),
        typeof(RouteOptions),
    };

    [Theory]
    [MemberData(nameof(ApplicationWideSettings))]
    public void TheHostsApplicationWideSettingsAreAsWithoutTheLibrary(Type options)
        => Assert.Equal(Shape(OptionsOf(_plain, options)), Shape(OptionsOf(_withLibrary, options)));

    [Fact]
    public void TheHostsPipelineGetsNoStartupFilter()
        => Assert.Equal(
            _plain.Services.GetServices<IStartupFilter>().Select(filter => filter.GetType()),
            _withLibrary.Services.GetServices<IStartupFilter>().Select(filter => filter.GetType()));

    private const string MinimalEchoPath = "/host/minimal";

    /// <summary>Metadata the host puts on the library's endpoints through what the mapping call returns.</summary>
    private static readonly object LibraryConvention = new();

    /// <summary>Metadata the host adds last, through the finishing convention of what the mapping call returns.</summary>
    private static readonly object FinalLibraryConvention = new();

    /// <summary>A pattern of the host's that two-segment paths of the library also match.</summary>
    private const string HostPagePattern = "/{section}/{page}";

    private static object OptionsOf(WebApplication app, Type options)
    {
        var accessor = app.Services.GetRequiredService(typeof(IOptions<>).MakeGenericType(options));
        return accessor.GetType().GetProperty(nameof(IOptions<object>.Value))!.GetValue(accessor)!;
    }

    /// <summary>
    /// What an options object holds, member by member, nested settings objects followed one level down: a value as
    /// itself, a delegate as the method it calls, a list as the types of what it holds, anything else as its type.
    /// </summary>
    private static List<string> Shape(object options, string prefix = "", int depth = 0)
    {
        var shape = new List<string>();
        foreach (var property in options.GetType().GetProperties(BindingFlags.Public | BindingFlags.Instance))
        {
            if (property.GetIndexParameters().Length > 0 || !property.CanRead)
                continue;

            var name = prefix + property.Name;
            object? value;
            try
            {
                value = property.GetValue(options);
            }
            catch (TargetInvocationException exception)
            {
                shape.Add($"{name} throws {exception.InnerException?.GetType().Name}");
                continue;
            }

            switch (value)
            {
                case null:
                    shape.Add($"{name} = null");
                    break;

                case string or bool or Enum or TimeSpan or Type or CultureInfo:
                    shape.Add($"{name} = {value}");
                    break;

                case var primitive when primitive.GetType().IsPrimitive:
                    shape.Add($"{name} = {primitive}");
                    break;

                case Delegate function:
                    shape.Add($"{name} = {function.Method.DeclaringType?.FullName}.{function.Method.Name}");
                    break;

                case DefaultJsonTypeInfoResolver resolver:
                    shape.Add($"{name} = {resolver.GetType().FullName}");
                    shape.AddRange(resolver.Modifiers.Select(modifier =>
                        $"{name}.Modifiers: {modifier.Method.DeclaringType?.FullName}.{modifier.Method.Name}"));
                    break;

                case IDictionary entries:
                    shape.Add($"{name} = {{{string.Join(", ", entries.Keys.Cast<object>().Order().Select(key =>
                        $"{key}: {Describe(entries[key])}"))}}}");
                    break;

                case IEnumerable items:
                    shape.Add($"{name} = [{string.Join(", ", items.Cast<object?>().Select(item => item?.GetType().FullName))}]");
                    break;

                case var settings when depth == 0 && settings.GetType().IsClass:
                    shape.Add($"{name} : {settings.GetType().FullName}");
                    shape.AddRange(Shape(settings, name + ".", depth + 1));
                    break;

                default:
                    shape.Add($"{name} : {value.GetType().FullName}");
                    break;
            }
        }

        return shape;
    }

    private static string? Describe(object? value) => value is Type type ? type.FullName : value?.GetType().FullName;

    private static async Task<(int Status, string? ContentType, JsonNode? Body)> SendAsync(
        WebApplication app, string method, string path, string? json)
    {
        using var client = app.GetTestClient();
        client.BaseAddress = TestServerAddress.BaseAddress;
        using var request = new HttpRequestMessage(new HttpMethod(method), path);
        if (json != null)
            request.Content = new StringContent(json, System.Text.Encoding.UTF8, MediaTypeNames.Application.Json);

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var text = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        // The trace identifier differs from one request to the next and says nothing about the host's settings
        var body = text.Length == 0 ? null : TryParse(text);
        if (body is JsonObject problem)
            problem.Remove("traceId");

        return ((int)response.StatusCode, response.Content.Headers.ContentType?.ToString(), body);
    }

    private static JsonNode? TryParse(string text)
    {
        try
        {
            return JsonNode.Parse(text);
        }
        catch (System.Text.Json.JsonException)
        {
            return JsonValue.Create(text);
        }
    }
}
