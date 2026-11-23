// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class ClientIdMetadataDocumentTests
{
    /// <summary>
    /// One request names the client at several steps - the per-client pushed request rule, the request object or
    /// request_uri it arrives with, the client validation, the client authentication of a pushed request - and a refused
    /// document is fetched once for all of them. Section 6.2 has the server "MUST NOT cache error responses" and "MUST
    /// NOT cache documents which are invalid", which a refusal held by the request that judged it does not do, and
    /// "MAY implement rate limiting or other measures to avoid repeatedly fetching".
    /// </summary>
    [Theory]
    [InlineData(Arrival.Query, Unavailable.NotFound)]
    [InlineData(Arrival.Query, Unavailable.AnotherClientId)]
    [InlineData(Arrival.Query, Unavailable.SharedSecret)]
    [InlineData(Arrival.RequestObject, Unavailable.NotFound)]
    [InlineData(Arrival.RequestUri, Unavailable.NotFound)]
    [InlineData(Arrival.Pushed, Unavailable.NotFound)]
    [InlineData(Arrival.Pushed, Unavailable.AnotherClientId)]
    public async Task ARefusedDocument_IsFetchedOncePerRequest(Arrival arrival, Unavailable why)
    {
        Arrange(why);
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await SendAsync(client, discovery, arrival);

        Assert.False(response.IsSuccessStatusCode);
        Assert.Equal(1, _origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// The refusal dies with the request that judged it: section 6.2 has the server "MUST NOT cache error responses",
    /// so the next request asks the client's server again.
    /// </summary>
    [Theory]
    [InlineData(Unavailable.NotFound)]
    [InlineData(Unavailable.AnotherClientId)]
    public async Task ARefusedDocument_IsFetchedAgainByTheNextRequest(Unavailable why)
    {
        Arrange(why);
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        using (await SendAsync(client, discovery, Arrival.Query))
            Assert.Equal(1, _origin.RequestsTo(ClientId));

        using (await SendAsync(client, discovery, Arrival.Query))
            Assert.Equal(2, _origin.RequestsTo(ClientId));
    }

    /// <summary>
    /// Sends one authorization request for <paramref name="clientId"/> the way <paramref name="arrival"/> names.
    /// </summary>
    private static Task<HttpResponseMessage> SendAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        Arrival arrival,
        string clientId = ClientId)
    {
        var parameters = CodeFlowParameters(clientId, GeneratePkcePair().Challenge);
        switch (arrival)
        {
            case Arrival.Query:
                return client.GetAsync(
                    QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, parameters),
                    TestContext.Current.CancellationToken);

            case Arrival.RequestObject:
                return client.GetAsync(
                    QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
                    {
                        [AuthorizationRequest.Parameters.ClientId] = clientId,
                        [AuthorizationRequest.Parameters.Request] = Unsecured(parameters),
                    }),
                    TestContext.Current.CancellationToken);

            case Arrival.RequestUri:
                return client.GetAsync(
                    QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
                    {
                        [AuthorizationRequest.Parameters.ClientId] = clientId,
                        [AuthorizationRequest.Parameters.RequestUri] = "https://client.example.com/oauth/request.jwt",
                    }),
                    TestContext.Current.CancellationToken);

            case Arrival.Pushed:
                return FormPostHelpers.PostFormAsync(client, discovery.PushedAuthorizationRequestEndpoint!, parameters);

            default:
                throw new ArgumentOutOfRangeException(nameof(arrival), arrival, null);
        }
    }

    /// <summary>
    /// An Unsecured JWS (RFC 7515 appendix A.5) carrying <paramref name="parameters"/> as its claims.
    /// </summary>
    private static string Unsecured(Dictionary<string, string> parameters)
    {
        var claims = new JsonObject();
        foreach (var (name, value) in parameters)
            claims[name] = value;

        var header = new JsonObject { [JwtClaimTypes.Algorithm] = SigningAlgorithms.None };
        return string.Join(
            '.',
            Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString())),
            Base64Url.EncodeToString(Encoding.UTF8.GetBytes(claims.ToJsonString())),
            string.Empty);
    }

    public enum Arrival
    {
        Query,
        RequestObject,
        RequestUri,
        Pushed,
    }
}
