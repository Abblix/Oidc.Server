// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// An unsupported value inside a signed request object is answered as the same value is in the query.
/// </summary>
public partial class PromptReturnTripTests
{
    /// <summary>
    /// How a signed request object reaches the server.
    /// </summary>
    public enum RequestObjectPassing
    {
        ByValue,
        ByReference,
        Pushed,
    }

    public static TheoryData<string, string, RequestObjectPassing> UnsupportedValuesByPassing()
    {
        (string Name, string Value)[] unsupported =
        [
            (AuthorizationRequest.Parameters.ResponseMode, "bogus"),
            (AuthorizationRequest.Parameters.Display, "hologram"),
            (AuthorizationRequest.Parameters.CodeChallengeMethod, "S1"),
        ];

        var data = new TheoryData<string, string, RequestObjectPassing>();
        foreach (var (name, value) in unsupported)
        {
            foreach (var passing in Enum.GetValues<RequestObjectPassing>())
                data.Add(name, value, passing);
        }

        return data;
    }

    /// <summary>
    /// An unsupported value inside a signed request object gets the answer the same value gets in the query: a
    /// 400 for a response mode, which no error response can be delivered in, and invalid_request at the redirect
    /// URI for a display value and a code challenge method. A pushed object is answered by the pushed authorization
    /// endpoint itself (RFC 9126, section 2.3), so there the error code is what has to match.
    /// </summary>
    [Theory]
    [MemberData(nameof(UnsupportedValuesByPassing))]
    public async Task UnsupportedValue_InRequestObject_IsAnsweredAsInTheQuery(
        string name,
        string value,
        RequestObjectPassing passing)
    {
        var served = new RequestObjectServer();
        var (client, host) = StartServing(served);
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);

        var query = AuthorizeParameters(Prompts.Login);
        query[name] = value;
        using var viaQuery = await client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, query), TestContext.Current.CancellationToken);
        var error = await ErrorOfAsync(viaQuery);
        Assert.Equal(ErrorCodes.InvalidRequest, error);

        var (clientId, clientSecret, requestObject) = await SignedRequestAsync(
            client,
            discovery,
            Prompts.Login,
            new Dictionary<string, string> { [name] = value },
            requestUris: [RequestObjectServer.Address]);

        using var viaObject = await SendRequestObjectAsync(
            client, discovery, clientId, clientSecret, requestObject, passing, served);

        if (passing != RequestObjectPassing.Pushed)
            Assert.Equal(viaQuery.StatusCode, viaObject.StatusCode);

        Assert.Equal(error, await ErrorOfAsync(viaObject));
    }

    /// <summary>
    /// An empty response mode inside a request object is no response mode, as an empty one in the query is: the
    /// request goes on to the login page rather than being refused.
    /// </summary>
    [Fact]
    public async Task EmptyResponseMode_InRequestObject_IsTakenAsAbsent()
    {
        var (client, _, host) = Start();
        using var _ = host;
        var discovery = await FetchDiscoveryAsync(client);
        var (clientId, clientSecret, requestObject) = await SignedRequestAsync(
            client,
            discovery,
            Prompts.Login,
            new Dictionary<string, string> { [AuthorizationRequest.Parameters.ResponseMode] = string.Empty });

        var sentTo = await RedirectOf(client, await FirstLegAsync(
            client, discovery, clientId, clientSecret, requestObject, pushed: false));

        Assert.Equal(LoginPath, PathOf(sentTo));
    }

    /// <summary>
    /// Sends a signed request object the way <paramref name="passing"/> names and returns the server's answer.
    /// </summary>
    private static async Task<HttpResponseMessage> SendRequestObjectAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string clientSecret,
        string requestObject,
        RequestObjectPassing passing,
        RequestObjectServer served)
    {
        switch (passing)
        {
            case RequestObjectPassing.ByValue:
                return await client.GetAsync(
                    await FirstLegAsync(client, discovery, clientId, clientSecret, requestObject, pushed: false),
                    TestContext.Current.CancellationToken);

            case RequestObjectPassing.ByReference:
                served.Content = requestObject;
                return await client.GetAsync(
                    Authorize(discovery, clientId, RequestObjectServer.Address),
                    TestContext.Current.CancellationToken);

            case RequestObjectPassing.Pushed:
                return await FormPostHelpers.PostFormAsync(
                    client,
                    discovery.PushedAuthorizationRequestEndpoint!,
                    new Dictionary<string, string>
                    {
                        [AuthorizationRequest.Parameters.ClientId] = clientId,
                        [ClientRequest.Parameters.ClientSecret] = clientSecret,
                        [AuthorizationRequest.Parameters.Request] = requestObject,
                    });

            default:
                throw new ArgumentOutOfRangeException(nameof(passing), passing, null);
        }
    }

    /// <summary>
    /// Answers the server's fetch of a request_uri with the request object the test sets, standing in for the
    /// client's own web server.
    /// </summary>
    private sealed class RequestObjectServer : ISecureHttpFetcher
    {
        public const string Address = "https://client.example.com/request.jwt";

        public string? Content { get; set; }

        public Task<Result<T, OidcError>> FetchAsync<T>(Uri uri)
            => Task.FromResult<Result<T, OidcError>>((T)(object)Content!);
    }

    /// <summary>
    /// The server over a signed-in end user and a client web server serving request objects.
    /// </summary>
    private (HttpClient Client, IDisposable Host) StartServing(RequestObjectServer served)
    {
        var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.Replace(ServiceDescriptor.Singleton<IAuthSessionService>(new SignedInEndUser()));
            services.Replace(ServiceDescriptor.Singleton<ISecureHttpFetcher>(served));
        }));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        return (client, host);
    }

    /// <summary>
    /// The error an authorization response carries: in the redirect it sends, or in the body of a 400.
    /// </summary>
    private static async Task<string?> ErrorOfAsync(HttpResponseMessage response)
    {
        if (response.Headers.Location is { } location)
            return QueryValue(location, ResponseParameters.Error);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        return body[ResponseParameters.Error]?.GetValue<string>();
    }
}
