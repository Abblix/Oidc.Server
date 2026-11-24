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
using Abblix.Oidc.Server.E2E.Tests.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 3.2: a server supporting browser-based applications "MUST ensure the
/// token endpoint supports the necessary CORS [WHATWG.CORS] header fields", and the endpoints it provides such an
/// application, "such as metadata URLs, dynamic client registration, revocation, introspection, discovery, or user
/// info endpoints", "MUST also send the CORS header fields to allow access"; a pushed authorization request is posted
/// by the application in the same way. A browser asks first with a preflight for a request other than a simple one: a
/// JSON body, an Authorization header, or the PUT and DELETE of RFC 7592. Run on both hosts.
/// </summary>
public class CorsEndpointTests(TestFactory factory) : TestBase(factory)
{
    private const string Origin = "https://spa.example.com";

    public enum Endpoint { Token, Revocation, Introspection, UserInfo, Registration, PushedAuthorization, ClientConfiguration }

    [Theory]
    [InlineData(Endpoint.Token, "POST")]
    [InlineData(Endpoint.Revocation, "POST")]
    [InlineData(Endpoint.Introspection, "POST")]
    [InlineData(Endpoint.UserInfo, "GET")]
    [InlineData(Endpoint.UserInfo, "POST")]
    [InlineData(Endpoint.Registration, "POST")]
    [InlineData(Endpoint.PushedAuthorization, "POST")]
    [InlineData(Endpoint.ClientConfiguration, "GET")]
    [InlineData(Endpoint.ClientConfiguration, "PUT")]
    [InlineData(Endpoint.ClientConfiguration, "DELETE")]
    public async Task A_preflight_to_an_endpoint_a_browser_application_calls_is_allowed(Endpoint endpoint, string method)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Options, AddressOf(discovery, endpoint));
        request.Headers.Add("Origin", Origin);
        request.Headers.Add("Access-Control-Request-Method", method);
        request.Headers.Add("Access-Control-Request-Headers", "authorization, content-type");
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.NoContent, response.StatusCode);
        Assert.Equal("*", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
    }

    /// <summary>
    /// The response itself carries the header too, a refusal included, so the application can read why it was refused,
    /// whatever media type it posted: registration answers a body of another media type through a route of its own.
    /// </summary>
    [Theory]
    [InlineData(Endpoint.Registration, MediaTypeNames.Application.Json)]
    [InlineData(Endpoint.Registration, MediaTypeNames.Text.Plain)]
    [InlineData(Endpoint.PushedAuthorization, "application/x-www-form-urlencoded")]
    [InlineData(Endpoint.Introspection, "application/x-www-form-urlencoded")]
    public async Task A_request_from_another_origin_is_answered_readable(Endpoint endpoint, string mediaType)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var request = new HttpRequestMessage(HttpMethod.Post, AddressOf(discovery, endpoint))
        {
            Content = new StringContent(
                mediaType == MediaTypeNames.Application.Json ? "{}" : "client_id=unknown",
                Encoding.UTF8,
                mediaType),
        };
        request.Headers.Add("Origin", Origin);
        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal("*", Assert.Single(response.Headers.GetValues("Access-Control-Allow-Origin")));
    }

    private static Uri AddressOf(DiscoveryDocument discovery, Endpoint endpoint) => endpoint switch
    {
        Endpoint.Token => discovery.TokenEndpoint,
        Endpoint.Revocation => discovery.RevocationEndpoint!,
        Endpoint.Introspection => discovery.IntrospectionEndpoint!,
        Endpoint.UserInfo => discovery.UserInfoEndpoint!,
        Endpoint.Registration => discovery.RegistrationEndpoint!,
        Endpoint.PushedAuthorization => discovery.PushedAuthorizationRequestEndpoint!,
        Endpoint.ClientConfiguration => new Uri(discovery.RegistrationEndpoint! + "/some-client"),
        _ => throw new ArgumentOutOfRangeException(nameof(endpoint), endpoint, null),
    };
}
