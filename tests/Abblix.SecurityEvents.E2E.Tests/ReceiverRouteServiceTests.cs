// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net.Http.Headers;
using System.Net.Mime;
using System.Reflection;
using Abblix.SecurityEvents.BackChannelLogout;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.MinimalApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Xunit;

namespace Abblix.SecurityEvents.E2E.Tests;

/// <summary>
/// A receiver route mapped on a host that has not registered its handler names the missing service, rather than
/// refusing every request as an unsupported media type.
/// </summary>
/// <remarks>
/// Minimal API decides when the route is built whether a parameter is a service, and without a registration it would
/// read the handler from a JSON body, which a sender never posts.
/// </remarks>
public sealed class ReceiverRouteServiceTests
{
    private const string LogoutRoute = "/backchannel-logout";
    private const string PushRoute = "/push";

    public static TheoryData<string, Type> Handlers() => new()
    {
        { LogoutRoute, typeof(BackChannelLogoutHandler) },
        { PushRoute, typeof(PushDeliveryHandler) },
    };

    public static TheoryData<string, string, Type> Posts() => new()
    {
        { LogoutRoute, MediaTypeNames.Application.FormUrlEncoded, typeof(BackChannelLogoutHandler) },
        { PushRoute, SecurityEventTokenMediaTypes.SecurityEventToken, typeof(PushDeliveryHandler) },
    };

    /// <summary>
    /// The handler parameter of the route is declared as a service, so a check of the host's endpoints finds it.
    /// </summary>
    [Theory]
    [MemberData(nameof(Handlers))]
    public async Task TheHandlerParameter_IsDeclaredAsAService(string route, Type handler)
    {
        await using var host = await StartAsync();

        var method = ((IEndpointRouteBuilder)host).DataSources
            .SelectMany(source => source.Endpoints)
            .OfType<RouteEndpoint>()
            .Single(endpoint => endpoint.RoutePattern.RawText == route)
            .Metadata.GetMetadata<MethodInfo>();

        var parameter = Assert.Single(method!.GetParameters(), candidate => candidate.ParameterType == handler);
        Assert.Contains(parameter.GetCustomAttributes(), attribute => attribute is IFromServiceMetadata);
    }

    /// <summary>
    /// A request in the form a sender posts reaches the service lookup, which names the handler nobody registered.
    /// </summary>
    [Theory]
    [MemberData(nameof(Posts))]
    public async Task ARequestWithoutTheHandlerRegistered_NamesTheMissingService(
        string route,
        string contentType,
        Type handler)
    {
        await using var host = await StartAsync();
        using var client = host.GetTestClient();
        using var content = new StringContent("token");
        content.Headers.ContentType = MediaTypeHeaderValue.Parse(contentType);

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => client.PostAsync(route, content, TestContext.Current.CancellationToken));

        Assert.Contains(handler.FullName!, refusal.Message, StringComparison.Ordinal);
    }

    private static async Task<WebApplication> StartAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();
        var host = builder.Build();
        host.MapBackChannelLogoutEndpoint(LogoutRoute);
        host.MapPushDeliveryEndpoint(PushRoute);
        await host.StartAsync(TestContext.Current.CancellationToken);
        return host;
    }
}
