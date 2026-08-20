// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Headers;
using System.Net.Http.Json;
using System.Net.Mime;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.MinimalApi.E2E.Tests;

/// <summary>
/// The Minimal API counterpart of the MVC suite's <c>SignedUserInfoTests</c>: a client that registers
/// <c>userinfo_signed_response_alg</c> gets its claims as a signed JWT rather than as a JSON object
/// (OpenID Connect Core 1.0 section 5.3.2).
/// </summary>
/// <remarks>
/// Deliberately the same two cases as the MVC suite. The formatters are separate implementations of one
/// contract, so the defect this pair exists to catch is one adapter signing while the other quietly answers
/// JSON - which no single-adapter test can see.
/// </remarks>
public sealed class SignedUserInfoTests(TestFactory factory) : IClassFixture<TestFactory>
{
    private HttpClient CreateClient() => factory.CreateClient(new WebApplicationFactoryClientOptions
    {
        AllowAutoRedirect = false,
        BaseAddress = TestFactory.BaseAddress,
    });

    private static async Task<(string ClientId, string ClientSecret)> RegisterSigningClientAsync(
        HttpClient client, JsonObject discovery)
    {
        var endpoint = OidcFlows.Endpoint(
            discovery, ConfigurationResponse.Parameters.RegistrationEndpoint);

        var response = await client.PostAsJsonAsync(
            endpoint,
            new JsonObject
            {
                [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
                [RegistrationMembers.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
                [RegistrationMembers.ResponseTypes] = new JsonArray { ResponseTypes.Code },
                [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
                [RegistrationMembers.UserInfoSignedResponseAlg] = SigningAlgorithms.RS256,
            },
            TestContext.Current.CancellationToken);

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"registration failed: {(int)response.StatusCode} {raw}");

        var registered = JsonNode.Parse(raw)!.AsObject();
        return (
            registered[ClientRequest.Parameters.ClientId]!.GetValue<string>(),
            registered[ClientRequest.Parameters.ClientSecret]!.GetValue<string>());
    }

    private static async Task<HttpResponseMessage> CallUserInfoAsync(
        HttpClient client, JsonObject discovery, string accessToken)
    {
        var endpoint = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.UserInfoEndpoint);

        var request = new HttpRequestMessage(HttpMethod.Get, endpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);

        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// The response is a JWT served as <c>application/jwt</c>, and it verifies against the provider's published
    /// keys for this client - a well-formed token signed with the wrong key is what a client rejects in
    /// production and what a shape-only assertion would pass.
    /// </summary>
    [Fact]
    public async Task A_client_registering_a_signing_algorithm_gets_a_jwt_that_verifies_against_the_published_keys()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        var (clientId, clientSecret) = await RegisterSigningClientAsync(client, discovery);
        var tokens = await client.AuthCodeTokensViaParAsync(discovery, clientId, clientSecret);
        var accessToken = tokens[ResponseParameters.AccessToken]!.GetValue<string>();

        var response = await CallUserInfoAsync(client, discovery, accessToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.IsSuccessStatusCode, $"/userinfo failed: {(int)response.StatusCode} {body}");
        Assert.Equal(MediaTypes.Jwt, response.Content.Headers.ContentType?.MediaType);

        var segments = body.Split('.');
        Assert.Equal(3, segments.Length);

        var header = JsonNode.Parse(Base64UrlDecodeToString(segments[0]))!.AsObject();
        Assert.Equal(SigningAlgorithms.RS256, header[JwtClaimTypes.Algorithm]!.GetValue<string>());

        var jwksUri = OidcFlows.Endpoint(discovery, ConfigurationResponse.Parameters.JwksUri);
        var serverJwks = JsonSerializer.Deserialize<JsonWebKeySet>(
            await client.GetStringAsync(jwksUri, TestContext.Current.CancellationToken));
        Assert.NotNull(serverJwks);

        var validationResult = await CreateValidator().ValidateAsync(body, new ValidationParameters
        {
            ValidateIssuer = iss => Task.FromResult(iss.TrimEnd('/') == TestConstants.Issuer.TrimEnd('/')),
            ValidateAudience = aud => Task.FromResult(aud.Contains(clientId)),
            ResolveIssuerSigningKeys = _ => serverJwks.Keys.ToAsyncEnumerable(),
        });

        Assert.True(validationResult.TryGetSuccess(out var token),
            validationResult.TryGetFailure(out var error)
                ? $"the signed UserInfo response did not validate: {error.Error} - {error.ErrorDescription}"
                : "the signed UserInfo response did not validate");

        Assert.False(
            string.IsNullOrEmpty(token.Payload.Subject),
            "the signed response carried no subject, so the client cannot tell whose claims these are");
    }

    /// <summary>
    /// A client that registers no signing algorithm keeps getting a plain JSON object, which is the side every
    /// existing deployment is on.
    /// </summary>
    [Fact]
    public async Task A_client_without_a_signing_algorithm_still_gets_plain_json()
    {
        var client = CreateClient();
        var discovery = await client.FetchDiscoveryAsync();

        var tokens = await client.AuthCodeTokensViaParAsync(
            discovery, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret);
        var accessToken = tokens[ResponseParameters.AccessToken]!.GetValue<string>();

        var response = await CallUserInfoAsync(client, discovery, accessToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.IsSuccessStatusCode, $"/userinfo failed: {(int)response.StatusCode} {body}");
        Assert.Equal(MediaTypeNames.Application.Json, response.Content.Headers.ContentType?.MediaType);
        Assert.NotNull(JsonNode.Parse(body)?.AsObject());
    }

    private static IJsonWebTokenValidator CreateValidator()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        return services.BuildServiceProvider().GetRequiredService<IJsonWebTokenValidator>();
    }

    private static string Base64UrlDecodeToString(string value)
        => System.Text.Encoding.UTF8.GetString(System.Buffers.Text.Base64Url.DecodeFromChars(value));
}
