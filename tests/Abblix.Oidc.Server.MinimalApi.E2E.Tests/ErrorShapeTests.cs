// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Net.Http.Headers;
using Xunit;
using ClientParameters = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using Abblix.Oidc.Server.E2E.Tests;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// The shape of a refusal, which is the half of an endpoint a client depends on and a happy-path test never sees.
/// A status decides whether a client retries, and the <c>WWW-Authenticate</c> scheme decides what it retries WITH,
/// so getting either wrong sends a client round a loop it cannot win - and the server never learns of it.
/// </summary>
public sealed class ErrorShapeTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private HttpClient CreateClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        BaseAddress = TestFactory.BaseAddress,
    });

    /// <summary>
    /// Registers a throwaway client and returns the address the server nominates for reading it back, together
    /// with the token that address expects.
    /// </summary>
    private static async Task<(Uri Address, string AccessToken)> RegisterClientAsync(
        HttpClient client, JsonObject discovery)
    {
        var response = await client.PostAsync(
            OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.RegistrationEndpoint),
            JsonContent.Create(new JsonObject
            {
                [ClientRegistrationRequest.Parameters.ClientName] = $"error-shape-{Guid.NewGuid():N}",
                [ClientRegistrationRequest.Parameters.RedirectUris] =
                    new JsonArray { "https://client.example.com/callback" },
            }),
            TestContext.Current.CancellationToken);

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"registering a client failed: {(int)response.StatusCode} {raw}");

        var body = JsonNode.Parse(raw)!.AsObject();
        var address = body[ClientParameters.RegistrationClientUri];
        var token = body[ClientParameters.RegistrationAccessToken];
        Assert.NotNull(address);
        Assert.NotNull(token);

        return (new Uri(address.GetValue<string>()), token.GetValue<string>());
    }

    [Fact]
    public async Task Reading_a_client_with_someone_elses_token_answers_401_and_a_bearer_challenge()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var (address, _) = await RegisterClientAsync(client, discovery);

        var request = new HttpRequestMessage(HttpMethod.Get, address);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, "not-the-token-we-issued");
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // RFC 6750 section 3: a rejected bearer token is a 401 carrying the challenge, and the error travels in
        // the challenge rather than in a body - which is why the body assertion below is that there is none.
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        var challenge = Assert.Single(response.Headers.GetValues(HeaderNames.WWWAuthenticate));
        Assert.StartsWith(TokenTypes.Bearer, challenge, StringComparison.Ordinal);
        Assert.Contains(ErrorCodes.InvalidToken, challenge, StringComparison.Ordinal);

        // No realm, unlike the challenges from CIBA, introspection, revocation and the token endpoint, which all
        // pass the issuer: the client-management formatters call Format without one. RFC 6750 section 3 makes
        // realm optional, so this is a difference between endpoints rather than a defect - asserted so that
        // making them consistent is a deliberate change with a failing test, not a silent one.
        Assert.DoesNotContain("realm=", challenge, StringComparison.Ordinal);

        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(string.Empty, body);
    }

    [Fact]
    public async Task Reading_a_client_with_its_own_token_still_succeeds()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();
        var (address, accessToken) = await RegisterClientAsync(client, discovery);

        var request = new HttpRequestMessage(HttpMethod.Get, address);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        // The control for the test above: without it, a read endpoint broken into refusing everything would
        // satisfy the 401 assertion and read as proof that the challenge works.
        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.False(response.Headers.Contains(HeaderNames.WWWAuthenticate));
    }
}
