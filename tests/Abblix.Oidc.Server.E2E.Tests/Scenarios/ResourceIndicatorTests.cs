// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 8707 Resource Indicators end-to-end against the test OIDC provider. The client_credentials
/// grant is the canonical resource-indicator scenario: it is a direct grant with no prior
/// authorization step, so the requested resource is itself the authorized audience and must land
/// in the issued access token's aud claim.
/// </summary>
public class ResourceIndicatorTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task ClientCredentials_with_registered_resource_sets_token_audience()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
        });

        var payload = DecodeJwtPayload(tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        var audiences = ExtractAudiences(payload);

        // The requested resource is the audience; the client id is NOT folded in alongside it.
        Assert.Contains(TestConstants.ApiResource, audiences);
        Assert.DoesNotContain(TestConstants.ClientCredentialsClientId, audiences);
    }

    [Fact]
    public async Task ClientCredentials_without_resource_falls_back_to_issuer_audience()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var payload = DecodeJwtPayload(tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        var audiences = ExtractAudiences(payload);

        // No resource indicator: the audience names this server, which is who consumes the token when no
        // resource was asked for. RFC 9068 Section 4 has a resource server reject a token whose audience does
        // not name it, so the client id - the party that asked rather than the one that reads - would be a
        // value every conforming consumer must refuse.
        Assert.Contains(discovery.Issuer.OriginalString, audiences);
        Assert.DoesNotContain(TestConstants.ClientCredentialsClientId, audiences);
    }

    /// <summary>
    /// Introspection validates the audience of the token it is given, so a token minted for a named resource
    /// has to be recognised there too - the resource is the consumer, and reporting the token inactive would
    /// tell the caller it was never issued.
    /// </summary>
    [Fact]
    public async Task Access_token_for_a_named_resource_introspects_as_active()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
        });
        var accessToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        Assert.NotNull(discovery.IntrospectionEndpoint);
        using var introspectRequest = new HttpRequestMessage(HttpMethod.Post, discovery.IntrospectionEndpoint);
        introspectRequest.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [IntrospectionRequest.Parameters.Token] = accessToken,
            [IntrospectionRequest.Parameters.TokenTypeHint] = UserInfoRequest.Parameters.AccessToken,
        });

        var response = await client.SendAsync(introspectRequest, TestContext.Current.CancellationToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"introspect failed: {(int)response.StatusCode} {raw}");

        var body = JsonNode.Parse(raw)?.AsObject();
        Assert.NotNull(body);
        Assert.True(
            body[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>(),
            $"a token minted for {TestConstants.ApiResource} was reported inactive: {raw}");
    }

    /// <summary>
    /// The positive half of the audience check at UserInfo: a token whose request named no resource carries
    /// the issuer, which is the identifier this endpoint expects for itself, and is accepted. Without this
    /// the rejection below would also pass against an endpoint that simply refuses everything.
    /// </summary>
    [Fact]
    public async Task UserInfo_accepts_a_token_whose_audience_is_the_issuer()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var accessToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        var audiences = ExtractAudiences(DecodeJwtPayload(accessToken));
        Assert.Contains(discovery.Issuer.OriginalString, audiences);

        var response = await SendUserInfoAsync(client, discovery, accessToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"/userinfo rejected an issuer-audienced token: {raw}");
    }

    /// <summary>
    /// RFC 9068 Section 4: "The JWT access token MUST be rejected if aud does not contain a resource indicator
    /// of the current resource server as a valid audience." UserInfo is a protected resource
    /// (OpenID Connect Core 1.0 Section 1.2), so a token minted for someone else's API does not open it -
    /// which is the cross-JWT confusion Section 5 exists to prevent.
    /// </summary>
    [Fact]
    public async Task UserInfo_rejects_a_token_minted_for_another_resource()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var accessToken = await ObtainResourceScopedUserAccessTokenAsync(client, discovery);

        var audiences = ExtractAudiences(DecodeJwtPayload(accessToken));
        Assert.Equal([TestConstants.ApiResource], audiences);

        var response = await SendUserInfoAsync(client, discovery, accessToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.False(
            response.IsSuccessStatusCode,
            $"/userinfo accepted a token minted for {TestConstants.ApiResource}: {raw}");
        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }

    private static async Task<HttpResponseMessage> SendUserInfoAsync(
        HttpClient client, DiscoveryDocument discovery, string accessToken)
    {
        Assert.NotNull(discovery.UserInfoEndpoint);
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    /// <summary>
    /// Drives the auth-code flow for the confidential client while naming the registered resource, so the
    /// resulting access token belongs to a real end-user and is audience-restricted to that resource.
    /// </summary>
    private static async Task<string> ObtainResourceScopedUserAccessTokenAsync(
        HttpClient client, DiscoveryDocument discovery)
    {
        var (verifier, challenge) = GeneratePkcePair();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
        });

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
        });

        return tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
    }

    [Fact]
    public async Task ClientCredentials_with_unregistered_resource_is_rejected_as_invalid_target()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.Resource] = "https://unregistered.example.com/api",
        });

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.False(response.IsSuccessStatusCode,
            $"Expected invalid_target rejection, but got {(int)response.StatusCode}: {raw}");
        var error = JsonNode.Parse(raw)?.AsObject();
        Assert.Equal(ErrorCodes.InvalidTarget, error?[ResponseParameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// With a default resource indicator configured, a request naming no resource still gets an access token
    /// whose <c>aud</c> names the API rather than the client. RFC 9068 section 3 requires that default, and
    /// section 4 tells a resource server to reject a token whose <c>aud</c> does not name it - so a client
    /// identifier there is a value no conforming resource server should accept.
    /// </summary>
    [Fact]
    public async Task ClientCredentials_without_resource_uses_the_configured_default_indicator()
    {
        await using var host = CreateHostWithDefaultResource();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var payload = DecodeJwtPayload(tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        var audiences = ExtractAudiences(payload);

        Assert.Contains(TestConstants.ApiResource, audiences);
        Assert.DoesNotContain(TestConstants.ClientCredentialsClientId, audiences);
    }

    /// <summary>
    /// The default fills a gap rather than overriding a stated intent: a request naming a resource keeps it.
    /// </summary>
    [Fact]
    public async Task ClientCredentials_with_resource_keeps_it_over_the_default()
    {
        await using var host = CreateHostWithDefaultResource();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
        });

        var payload = DecodeJwtPayload(tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());

        Assert.Equal([TestConstants.ApiResource], ExtractAudiences(payload));
    }

    /// <summary>
    /// Builds an isolated host stating a default resource indicator, leaving the shared suite on the
    /// client-identifier fallback that every existing deployment still gets.
    /// </summary>
    private WebApplicationFactory<Program> CreateHostWithDefaultResource()
        => Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options => options.DefaultResourceIndicator = new Uri(TestConstants.ApiResource)))));

    /// <summary>
    /// A resource that publishes an encryption key gets its access token encrypted to that key, so the party
    /// named in <c>aud</c> can read the token minted for it. The proof is the recipient: the JWE header names
    /// the resource's own <c>kid</c>, not the server's, and a token encrypted to the server's key would be
    /// unreadable by the resource, which holds only the published public half.
    /// </summary>
    [Fact]
    public async Task ClientCredentials_with_resource_publishing_a_key_encrypts_the_token_to_it()
    {
        var resourceKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
        resourceKey = resourceKey with { KeyId = "orders-api-enc" };

        await using var host = CreateHostWithResourceKey(resourceKey);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
        });

        var accessToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        var segments = accessToken.Split('.');
        Assert.True(segments.Length == 5, $"Expected a JWE (5 segments), got {segments.Length}");

        var header = JsonNode.Parse(Base64UrlDecode(segments[0]))?.AsObject();
        Assert.NotNull(header);
        Assert.Equal(resourceKey.KeyId, header![JwtClaimTypes.KeyId]?.GetValue<string>());
    }

    /// <summary>
    /// Builds an isolated host where the registered resource publishes the given encryption key, and the
    /// server holds an encryption key of its own. Both being present is what makes the assertion meaningful:
    /// the token could have been encrypted to either, and the header says which one was chosen.
    /// </summary>
    private WebApplicationFactory<Program> CreateHostWithResourceKey(JsonWebKey resourceKey)
        => Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options =>
                        {
                            options.EncryptionKeys =
                            [
                                JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption) with
                                {
                                    KeyId = "server-enc",
                                },
                            ];
                            options.Resources =
                            [
                                new ResourceDefinition(new Uri(TestConstants.ApiResource))
                                {
                                    Jwks = new JsonWebKeySet([resourceKey]),
                                },
                            ];
                        }))));

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    // RFC 7519 section 4.1.3: aud is serialized as a single string when there is one value, or an array
    // when there are several. Normalize both shapes to a flat list for assertion.
    private static string[] ExtractAudiences(JsonObject payload) =>
        payload[JwtClaimTypes.Audience] switch
        {
            JsonArray array => array.Select(node => node!.GetValue<string>()).ToArray(),
            JsonValue value => [value.GetValue<string>()],
            _ => [],
        };
}
