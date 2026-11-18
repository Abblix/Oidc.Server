// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server


using Abblix.Oidc.Server.AspNetCore;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using Abblix.Oidc.Server.E2E.Tests;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// Beside each endpoint reading client metadata as JSON, another takes a body of any other media type, so routing does
/// not refuse it before its token is read. That one reads no metadata, so the API description, which lists the
/// endpoints a client calls, leaves it out and describes the JSON endpoint alone.
/// </summary>
public sealed class ClientMetadataMediaTypeRoutingTests(TestFactory factory) : IClassFixture<TestFactory>
{
    [Theory]
    [InlineData("POST")]
    [InlineData("PUT")]
    public void The_endpoint_of_another_media_type_is_left_out_of_the_description(string method)
    {
        var services = factory.Services;
        var routes = services.GetRequiredService<IOptions<OidcRouteOptions>>().Value;
        var route = method is "POST" ? routes.Register : routes.RegisterClient;

        var endpoints = services.GetRequiredService<EndpointDataSource>().Endpoints
            .OfType<RouteEndpoint>()
            .Where(candidate =>
                candidate.RoutePattern.RawText == route
                && candidate.Metadata.GetMetadata<HttpMethodMetadata>()!.HttpMethods.Contains(method))
            .ToList();

        var json = Assert.Single(endpoints, endpoint => endpoint.Metadata.GetMetadata<IAcceptsMetadata>() is not null);
        Assert.NotEqual(true, json.Metadata.GetMetadata<IExcludeFromDescriptionMetadata>()?.ExcludeFromDescription);

        var other = Assert.Single(endpoints, endpoint => endpoint != json);
        Assert.True(other.Metadata.GetMetadata<IExcludeFromDescriptionMetadata>()?.ExcludeFromDescription);
        Assert.True(other.Order > json.Order);
    }
}
