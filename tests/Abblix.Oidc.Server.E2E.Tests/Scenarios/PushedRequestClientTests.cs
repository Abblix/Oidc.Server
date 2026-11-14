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
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.WebUtilities;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A request_uri a client obtained by pushing its request (RFC 9126) is redeemed at the authorization endpoint only
/// under that client's own client_id: RFC 9101 section 6.3, which RFC 9126 section 4 applies to a pushed request,
/// requires the two values to be identical.
/// </summary>
/// <remarks>
/// Driven at the endpoint because the comparison has to run before the pushed request replaces the query, and only
/// the endpoint shows that the fetchers are composed in the order that keeps it so.
/// </remarks>
public class PushedRequestClientTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task ARequestUriPushedByOneClient_UnderAnotherClientsId_IsRefused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var requestUri = await PushAsync(client, discovery);

        var response = await AuthorizeAsync(client, discovery, TestConstants.ClientCredentialsClientId, requestUri);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidRequestUri, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// The pushing client's own id redeems the same kind of request_uri, so the refusal above is about the client
    /// named and not about the pushed request.
    /// </summary>
    [Fact]
    public async Task ARequestUriPushedByOneClient_UnderItsOwnId_IsServed()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var requestUri = await PushAsync(client, discovery);

        var response = await AuthorizeAsync(client, discovery, TestConstants.ConfidentialClientId, requestUri);

        Assert.True(
            response.StatusCode is HttpStatusCode.Redirect or HttpStatusCode.Found or HttpStatusCode.SeeOther,
            $"/authorize answered {(int)response.StatusCode}: " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    private static async Task<string> PushAsync(HttpClient client, DiscoveryDocument discovery)
    {
        Assert.NotNull(discovery.PushedAuthorizationRequestEndpoint);
        var (_, challenge) = GeneratePkcePair();

        var response = await client.PostAsync(
            discovery.PushedAuthorizationRequestEndpoint,
            new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
                [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
                [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
                [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
                [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
                [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
                [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
                [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            }),
            TestContext.Current.CancellationToken);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"pushing the request failed: {(int)response.StatusCode} {body}");
        return JsonNode.Parse(body)![PushedAuthorizationResponse.Parameters.RequestUri]!.GetValue<string>();
    }

    private static Task<HttpResponseMessage> AuthorizeAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string requestUri)
        => client.GetAsync(
            QueryHelpers.BuildUri(discovery.AuthorizationEndpoint, new Dictionary<string, string>
            {
                [AuthorizationRequest.Parameters.ClientId] = clientId,
                [AuthorizationRequest.Parameters.RequestUri] = requestUri,
            }),
            TestContext.Current.CancellationToken);
}
