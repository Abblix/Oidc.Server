// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net.Http.Headers;
using System.Net.Mime;
using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A client that registers <c>userinfo_signed_response_alg</c> gets its claims as a signed JWT rather than as a
/// JSON object (OpenID Connect Core 1.0 section 5.3.2).
/// </summary>
/// <remarks>
/// The signing arm of the UserInfo formatter had no test through either adapter, in a response that carries a
/// user's own claims. Every deployment reaching it is one that asked for cryptographic protection on exactly
/// that data, and the two failures it can hide are silent: falling back to plain JSON, which drops the
/// protection the client asked for without an error anywhere; and signing with the wrong key, issuer or
/// audience, which a client validating the token would reject while the server reports success.
///
/// The client is created through dynamic registration rather than by reconfiguring the host, because the
/// metadata that selects this arm is registration metadata, so registering is how a real deployment reaches it.
/// </remarks>
public class SignedUserInfoTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// Registers a confidential client asking for its UserInfo response to be signed, and returns its
    /// credentials.
    /// </summary>
    private static async Task<(string ClientId, string ClientSecret)> RegisterSigningClientAsync(
        HttpClient client, DiscoveryDocument discovery)
    {
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [RegistrationMembers.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
            [RegistrationMembers.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
            [RegistrationMembers.UserInfoSignedResponseAlg] = SigningAlgorithms.RS256,
        });

        return (
            registered[AuthorizationRequest.Parameters.ClientId]!.GetValue<string>(),
            registered[ClientRequest.Parameters.ClientSecret]!.GetValue<string>());
    }

    /// <summary>Runs the auth-code flow for the given client and returns its access token.</summary>
    private static async Task<string> ObtainAccessTokenAsync(
        HttpClient client, DiscoveryDocument discovery, string clientId, string clientSecret)
    {
        var (verifier, challenge) = GeneratePkcePair();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        });

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
        });

        return tokens[ResponseParameters.AccessToken]!.GetValue<string>();
    }

    private static async Task<HttpResponseMessage> CallUserInfoAsync(
        HttpClient client, DiscoveryDocument discovery, string accessToken)
    {
        Assert.NotNull(discovery.UserInfoEndpoint);

        var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);

        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// OpenID Connect Core 1.0 section 5.3.2: a signed UserInfo response is a JWT served as
    /// <c>application/jwt</c>. The media type is asserted on its own because a client dispatches on it - told
    /// <c>application/json</c>, it would try to parse the JWT as an object.
    ///
    /// The signature is then verified against the provider's published keys, with the issuer and audience
    /// checked, rather than merely observed to be present: a well-formed JWT signed with the wrong key is
    /// exactly what a client rejects in production and what a shape-only assertion would pass.
    /// </summary>
    [Fact]
    public async Task A_client_registering_a_signing_algorithm_gets_a_jwt_that_verifies_against_the_published_keys()
    {
        var httpClient = CreateClient();
        var discovery = await FetchDiscoveryAsync(httpClient);

        var (clientId, clientSecret) = await RegisterSigningClientAsync(httpClient, discovery);
        var accessToken = await ObtainAccessTokenAsync(httpClient, discovery, clientId, clientSecret);

        var response = await CallUserInfoAsync(httpClient, discovery, accessToken);
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);

        Assert.True(response.IsSuccessStatusCode, $"/userinfo failed: {(int)response.StatusCode} {body}");
        Assert.Equal(MediaTypes.Jwt, response.Content.Headers.ContentType?.MediaType);

        var segments = body.Split('.');
        Assert.Equal(3, segments.Length);

        var header = JsonNode.Parse(Base64UrlDecodeToString(segments[0]))!.AsObject();
        Assert.Equal(SigningAlgorithms.RS256, header[JwtClaimTypes.Algorithm]!.GetValue<string>());

        var serverJwks = JsonSerializer.Deserialize<JsonWebKeySet>(
            await httpClient.GetStringAsync(discovery.JwksUri, TestContext.Current.CancellationToken));
        Assert.NotNull(serverJwks);

        var validationResult = await CreateValidator().ValidateAsync(body, new ValidationParameters
        {
            ValidateIssuer = iss => Task.FromResult(
                iss.TrimEnd('/') == discovery.Issuer.AbsoluteUri.TrimEnd('/')),
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
    /// A client that registers no signing algorithm keeps getting a plain JSON object. Both arms live in one
    /// branch, so this pins the side that every existing deployment is on: turning signing on by default would
    /// break every client that never asked for it.
    /// </summary>
    [Fact]
    public async Task A_client_without_a_signing_algorithm_still_gets_plain_json()
    {
        var httpClient = CreateClient();
        var discovery = await FetchDiscoveryAsync(httpClient);

        var tokens = await ObtainConfidentialOfflineTokensAsync(httpClient, discovery);
        var accessToken = tokens[ResponseParameters.AccessToken]!.GetValue<string>();

        var response = await CallUserInfoAsync(httpClient, discovery, accessToken);
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
