// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <remarks>
/// RFC 9101 section 4: ""request" and "request_uri" parameters MUST NOT be included in Request Objects." Section 7
/// names the error for an object that breaks it: "invalid_request_object The request parameter contains an invalid
/// Request Object." At the pushed authorization request endpoint the rule applies through RFC 9126 section 2.1 step 3,
/// "Validate the pushed request as it would an authorization request sent to the authorization endpoint", and
/// section 3, "The rules for processing, signing, and encryption of the Request Object as defined in JAR [RFC9101]
/// apply".
/// </remarks>
public partial class JarRichAuthorizationRequestsTests
{
    /// <summary>Where the request object arrives.</summary>
    public enum Arrival
    {
        /// <summary>At the authorization endpoint, passed by value in the request parameter.</summary>
        AuthorizeByValue,

        /// <summary>At the authorization endpoint, fetched from the request_uri.</summary>
        AuthorizeByReference,

        /// <summary>At the pushed authorization request endpoint, in the request parameter, validated as at the
        /// authorization endpoint (RFC 9126 section 2.1 step 3).</summary>
        Pushed,
    }

    /// <summary>Which member forbidden by RFC 9101 section 4 the request object carries.</summary>
    public enum NestedMember
    {
        None,
        Request,
        RequestUri,

        /// <summary>The request member present with a JSON null value.</summary>
        NullRequest,

        /// <summary>The request_uri member present with a JSON null value.</summary>
        NullRequestUri,
    }

    public static TheoryData<Arrival, bool, NestedMember> NestedMemberRows()
    {
        var rows = new TheoryData<Arrival, bool, NestedMember>();
        var combinations =
            from arrival in Enum.GetValues<Arrival>()
            from strict in new[] { false, true }
            from member in Enum.GetValues<NestedMember>()
            select (arrival, strict, member);

        foreach (var (arrival, strict, member) in combinations)
            rows.Add(arrival, strict, member);

        return rows;
    }

    /// <summary>
    /// A request object including request or request_uri is refused with invalid_request_object on arrival, at the
    /// authorization endpoint before any end-user interaction and at the pushed authorization request endpoint, merged
    /// over the outer parameters and processed strictly; the same object without either member is served.
    /// </summary>
    [Theory]
    [MemberData(nameof(NestedMemberRows))]
    public async Task ARequestObjectIncludingRequestOrRequestUri_IsAnInvalidRequestObjectOnArrival(
        Arrival arrival,
        bool strict,
        NestedMember member)
    {
        var served = new ServedRequestObject();
        await using var baseHost = strict ? CreateStrictHost() : Factory.WithWebHostBuilder(_ => { });
        await using var host = baseHost.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.Replace(ServiceDescriptor.Singleton<ISecureHttpFetcher>(served))));
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var poster = await RegisterBasicSigningClientAsync(
            client, discovery, requireSignedRequestObject: false, requestUri: ServedRequestObject.Address);

        var requestObject = await SignNamingAsync(
            discovery, poster, poster.ClientId, GeneratePkcePair().Challenge, claims => Include(claims, member));

        var parameters = new Dictionary<string, string> { [AuthorizationRequest.Parameters.ClientId] = poster.ClientId };
        switch (arrival)
        {
            case Arrival.AuthorizeByValue or Arrival.Pushed:
                parameters[AuthorizationRequest.Parameters.Request] = requestObject;
                break;

            case Arrival.AuthorizeByReference:
                served.Content = requestObject;
                parameters[AuthorizationRequest.Parameters.RequestUri] = ServedRequestObject.Address;
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(arrival), arrival, null);
        }

        if (member == NestedMember.None)
        {
            await AssertServedAsync(client, discovery, poster, arrival, parameters);
            return;
        }

        using var response = await SendAsync(client, discovery, poster, arrival, parameters);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequestObject, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// The rows just outside RFC 9101 section 4: request_uri sent beside the object rather than inside it is the
    /// request's own fault, which keeps its invalid_request (RFC 9126 section 2.1 at the pushed authorization request
    /// endpoint, RFC 9101 section 5 at the authorization endpoint).
    /// </summary>
    [Theory]
    [InlineData(Arrival.AuthorizeByValue)]
    [InlineData(Arrival.Pushed)]
    public async Task ARequestUriBesideACleanRequestObject_StaysAnInvalidRequest(Arrival arrival)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var poster = await RegisterBasicSigningClientAsync(
            client, discovery, requireSignedRequestObject: false, requestUri: ServedRequestObject.Address);

        var parameters = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = poster.ClientId,
            [AuthorizationRequest.Parameters.Request] =
                await SignNamingAsync(discovery, poster, poster.ClientId, GeneratePkcePair().Challenge),
            [AuthorizationRequest.Parameters.RequestUri] = ServedRequestObject.Address,
        };

        using var response = await SendAsync(client, discovery, poster, arrival, parameters);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequest, await ErrorResponseReader.ErrorCodeOf(response));
    }

    /// <summary>
    /// An object fetched from a request_uri whose signature does not verify is answered with the same code as one
    /// including a forbidden member: both are an invalid Request Object (RFC 9101 sections 6.2 and 7), whichever way
    /// the object arrived.
    /// </summary>
    [Fact]
    public async Task ARequestObjectFetchedByReferenceWithABrokenSignature_IsAnInvalidRequestObject()
    {
        var served = new ServedRequestObject();
        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.Replace(ServiceDescriptor.Singleton<ISecureHttpFetcher>(served))));
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var poster = await RegisterBasicSigningClientAsync(
            client, discovery, requireSignedRequestObject: false, requestUri: ServedRequestObject.Address);

        var signed = await SignNamingAsync(discovery, poster, poster.ClientId, GeneratePkcePair().Challenge);
        var signatureStart = signed.LastIndexOf('.') + 1;
        served.Content = signed[..signatureStart] + (signed[signatureStart] == 'A' ? 'B' : 'A') + signed[(signatureStart + 1)..];

        using var response = await SendAsync(client, discovery, poster, Arrival.AuthorizeByReference,
            new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = poster.ClientId,
                [AuthorizationRequest.Parameters.RequestUri] = ServedRequestObject.Address,
            });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidRequestObject, await ErrorResponseReader.ErrorCodeOf(response));
    }

    private static void Include(JsonObject claims, NestedMember member)
    {
        switch (member)
        {
            case NestedMember.None:
                break;

            case NestedMember.Request:
                // An unsecured object of no parameters: what it holds is beside the point, its presence is the fault
                claims[AuthorizationRequest.Parameters.Request] = "eyJhbGciOiJub25lIn0.e30.";
                break;

            case NestedMember.RequestUri:
                claims[AuthorizationRequest.Parameters.RequestUri] = "https://client.example.com/another.jwt";
                break;

            case NestedMember.NullRequest:
                claims[AuthorizationRequest.Parameters.Request] = null;
                break;

            case NestedMember.NullRequestUri:
                claims[AuthorizationRequest.Parameters.RequestUri] = null;
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(member), member, null);
        }
    }

    private static async Task<HttpResponseMessage> SendAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        SigningClient poster,
        Arrival arrival,
        Dictionary<string, string> parameters)
    {
        switch (arrival)
        {
            case Arrival.AuthorizeByValue or Arrival.AuthorizeByReference:
                return await client.GetAsync(
                    QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters),
                    TestContext.Current.CancellationToken);

            case Arrival.Pushed:
                using (var request = new HttpRequestMessage(HttpMethod.Post, discovery.PushedAuthorizationRequestEndpoint!)
                {
                    Content = new FormUrlEncodedContent(parameters),
                })
                {
                    request.Headers.Authorization = BasicAuthenticationOf(poster);
                    return await client.SendAsync(request, TestContext.Current.CancellationToken);
                }

            default:
                throw new ArgumentOutOfRangeException(nameof(arrival), arrival, null);
        }
    }

    private static async Task AssertServedAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        SigningClient poster,
        Arrival arrival,
        Dictionary<string, string> parameters)
    {
        switch (arrival)
        {
            case Arrival.AuthorizeByValue or Arrival.AuthorizeByReference:
                Assert.False(string.IsNullOrEmpty(await AuthorizeAndExtractCodeAsync(client, discovery, parameters)));
                break;

            case Arrival.Pushed:
                using (var response = await SendAsync(client, discovery, poster, arrival, parameters))
                    Assert.Equal(HttpStatusCode.Created, response.StatusCode);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(arrival), arrival, null);
        }
    }
}
