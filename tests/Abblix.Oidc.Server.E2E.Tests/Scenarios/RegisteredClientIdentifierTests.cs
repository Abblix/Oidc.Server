// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using RequestMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9700 section 4.15.1: dynamic registration assigns every client_id unless the host accepts proposals, a token
/// the client credentials grant issues carries <c>idp</c> set to <c>client_credentials</c> in the token and in the
/// introspection response, and the user information endpoint answers only tokens issued for an end user (OpenID
/// Connect Core 1.0 section 5.3).
/// </summary>
public class RegisteredClientIdentifierTests(TestFactory factory) : TestBase(factory)
{
    private const string ProposedClientId = "e2e-subject";

    private const string PairwiseClientId = "e2e-pairwise-client-credentials";
    private const string ExchangingClientId = "e2e-client-credentials-exchange";

    [Fact]
    public async Task AProposedClientId_IsReplacedByOneTheServerAssigns()
    {
        using var host = HostAccepting(proposals: false);
        var (client, discovery) = await EndpointsAsync(host);

        var registered = await RegisterClientAsync(client, discovery, Proposing(ProposedClientId));

        var clientId = registered[ResponseMembers.ClientId]!.GetValue<string>();
        Assert.NotEqual(ProposedClientId, clientId);
        Assert.NotEmpty(clientId);
    }

    /// <summary>
    /// The proposal is ignored rather than judged, so one naming a client the server already holds is not refused.
    /// </summary>
    [Fact]
    public async Task AProposedClientIdAnotherClientHolds_IsIgnoredRatherThanRefused()
    {
        using var host = HostAccepting(proposals: false);
        var (client, discovery) = await EndpointsAsync(host);

        var registered = await RegisterClientAsync(client, discovery, Proposing(TestConstants.ConfidentialClientId));

        Assert.NotEqual(
            TestConstants.ConfidentialClientId, registered[ResponseMembers.ClientId]!.GetValue<string>());
    }

    [Fact]
    public async Task AHostAcceptingProposals_RegistersTheClientUnderTheProposedClientId()
    {
        using var host = HostAccepting(proposals: true);
        var (client, discovery) = await EndpointsAsync(host);

        var registered = await RegisterClientAsync(client, discovery, Proposing(ProposedClientId));

        Assert.Equal(ProposedClientId, registered[ResponseMembers.ClientId]!.GetValue<string>());
    }

    [Fact]
    public async Task AClientCredentialsToken_CarriesIdpClientCredentials_AndTheClientInSub()
    {
        using var host = HostAccepting(proposals: true);
        var (client, discovery) = await EndpointsAsync(host);
        var registered = await RegisterClientAsync(client, discovery, Proposing(ProposedClientId));

        var payload = DecodeJwtPayload(await ClientCredentialsTokenAsync(
            client, discovery, ProposedClientId, SecretOf(registered)));

        Assert.Equal(GrantTypes.ClientCredentials, payload[OidcClaimTypes.IdentityProvider]?.GetValue<string>());
        Assert.Equal(ProposedClientId, payload[JwtClaimTypes.Subject]?.GetValue<string>());
        Assert.Equal(ProposedClientId, payload[IanaClaimTypes.ClientId]?.GetValue<string>());
    }

    [Fact]
    public async Task APairwiseClientsClientCredentialsToken_CarriesIdpClientCredentials_AndItsPseudonymInSub()
    {
        using var host = HostAccepting(proposals: false);
        var (client, discovery) = await EndpointsAsync(host);

        var payload = DecodeJwtPayload(await ClientCredentialsTokenAsync(
            client, discovery, PairwiseClientId, TestConstants.ConfidentialClientSecret));

        Assert.Equal(GrantTypes.ClientCredentials, payload[OidcClaimTypes.IdentityProvider]?.GetValue<string>());
        Assert.Equal(PairwiseClientId, payload[IanaClaimTypes.ClientId]?.GetValue<string>());
        var subject = payload[JwtClaimTypes.Subject]?.GetValue<string>();
        Assert.False(string.IsNullOrEmpty(subject));
        Assert.NotEqual(PairwiseClientId, subject);
    }

    /// <summary>
    /// The endpoint refuses a client credentials token granted the openid scope.
    /// </summary>
    [Fact]
    public async Task UserInfo_RefusesAClientCredentialsToken()
    {
        using var host = HostAccepting(proposals: true);
        var (client, discovery) = await EndpointsAsync(host);
        var body = Proposing(ProposedClientId);
        body[RequestMembers.Scope] = Scopes.OpenId;
        var registered = await RegisterClientAsync(client, discovery, body);

        var token = await ClientCredentialsTokenAsync(
            client, discovery, ProposedClientId, SecretOf(registered), Scopes.OpenId);

        await AssertRefusedAtUserInfoAsync(client, discovery, token);
    }

    /// <summary>
    /// RFC 8693 section 2.1: an exchanged token is about the subject token's subject, so it stays the client's own.
    /// </summary>
    [Fact]
    public async Task AnExchangedClientCredentialsToken_KeepsIdp_AndUserInfoRefusesIt()
    {
        using var host = HostAccepting(proposals: false);
        var (client, discovery) = await EndpointsAsync(host);
        var subjectToken = await ClientCredentialsTokenAsync(
            client, discovery, ExchangingClientId, TestConstants.ConfidentialClientSecret, Scopes.OpenId);

        var exchanged = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.TokenExchange,
            [TokenRequest.Parameters.SubjectToken] = subjectToken,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.AccessToken,
            [ClientRequest.Parameters.ClientId] = ExchangingClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });
        var token = exchanged[TokenResponse.Parameters.AccessToken]!.GetValue<string>();

        Assert.Equal(
            GrantTypes.ClientCredentials, DecodeJwtPayload(token)[OidcClaimTypes.IdentityProvider]?.GetValue<string>());
        await AssertRefusedAtUserInfoAsync(client, discovery, token);
    }

    /// <summary>
    /// A caller other than the token's client is shown no claim about an end user, and <c>idp</c> for a client
    /// credentials token alone.
    /// </summary>
    [Theory]
    [InlineData(TestConstants.UnrestrictedClientId)]
    [InlineData(PairwiseClientId)]
    public async Task IntrospectionByAnotherClient_ShowsIdpForAClientCredentialsToken(string callerClientId)
    {
        using var host = HostAccepting(proposals: false);
        var (client, discovery) = await EndpointsAsync(host);
        var token = await ClientCredentialsTokenAsync(
            client, discovery, TestConstants.ClientCredentialsClientId, TestConstants.ConfidentialClientSecret);

        var introspected = await IntrospectAsync(client, discovery, token, callerClientId);

        Assert.True(introspected[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
        Assert.Equal(
            GrantTypes.ClientCredentials, introspected[OidcClaimTypes.IdentityProvider]?.GetValue<string>());
    }

    [Fact]
    public async Task IntrospectionByAnotherClient_ShowsNoIdpForAnEndUsersToken()
    {
        using var host = HostAccepting(proposals: false);
        var (client, discovery) = await EndpointsAsync(host);
        var token = await ObtainAccessTokenAsync(
            client, discovery, TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret);

        var introspected = await IntrospectAsync(client, discovery, token, TestConstants.UnrestrictedClientId);

        Assert.True(introspected[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
        Assert.False(introspected.ContainsKey(OidcClaimTypes.IdentityProvider));
    }

    private static async Task AssertRefusedAtUserInfoAsync(HttpClient client, DiscoveryDocument discovery, string token)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, token);

        using var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        Assert.Contains(
            response.Headers.WwwAuthenticate,
            challenge => challenge.Parameter?.Contains(ErrorCodes.InvalidToken, StringComparison.Ordinal) == true);
    }

    private static async Task<string> ClientCredentialsTokenAsync(
        HttpClient client, DiscoveryDocument discovery, string clientId, string clientSecret, string? scope = null)
    {
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [ClientRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = clientSecret,
        };
        if (scope is not null)
            form[TokenRequest.Parameters.Scope] = scope;

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, form);
        return tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
    }

    private static string SecretOf(JsonObject registered)
        => registered[ResponseMembers.ClientSecret]!.GetValue<string>();

    private static JsonObject Proposing(string clientId) => new()
    {
        [RequestMembers.ClientId] = clientId,
        [RequestMembers.ClientName] = "client proposing its client_id",
        [RequestMembers.GrantTypes] = new JsonArray(GrantTypes.ClientCredentials),
        [RequestMembers.ResponseTypes] = new JsonArray(),
        [RequestMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
    };

    /// <summary>
    /// A host whose access tokens are signed only, so the test reads their claims, holding beside the configured
    /// clients a pairwise client_credentials client, which may also introspect other clients' tokens, and a
    /// client_credentials client that may exchange its own tokens.
    /// </summary>
    private WebApplicationFactory<Program> HostAccepting(bool proposals)
    {
        var secret = new ClientSecret
        {
            Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(TestConstants.ConfidentialClientSecret)),
        };
        var pairwiseClient = new ClientInfo(PairwiseClientId)
        {
            ClientSecrets = [secret],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            AllowedGrantTypes = [GrantTypes.ClientCredentials],
            SubjectType = SubjectTypes.Pairwise,
            AllowCrossClientIntrospection = true,
        };
        var exchangingClient = new ClientInfo(ExchangingClientId)
        {
            ClientSecrets = [secret],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            AllowedGrantTypes = [GrantTypes.ClientCredentials, GrantTypes.TokenExchange],
        };

        return Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.PostConfigure<OidcOptions>(options =>
            {
                options.ServiceTokens.AccessToken.Encrypt = false;
                options.NewClientOptions = options.NewClientOptions with { AcceptProposedClientId = proposals };
            });
            services.PostConfigure<TestTenantSettings>(tenant =>
            {
                tenant.PairwiseSubject = new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) };
                tenant.Clients = [.. tenant.Clients, pairwiseClient, exchangingClient];
            });
        }));
    }

    private static async Task<(HttpClient Client, DiscoveryDocument Discovery)> EndpointsAsync(
        WebApplicationFactory<Program> host)
    {
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
        return (client, await FetchDiscoveryAsync(client));
    }
}
