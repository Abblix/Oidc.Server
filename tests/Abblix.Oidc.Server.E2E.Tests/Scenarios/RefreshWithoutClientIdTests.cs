// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 3.2.2: client_id is "OPTIONAL. The client identifier is needed when a
/// form of client authentication that relies on the parameter is used, or the grant_type requires identification of
/// public clients", and section 4.3.1 has the server "if a client_id is included in the request, ensure that the refresh
/// token was issued to the matching client": the refresh token grant asks no client_id of a public client, whose refresh
/// token names the client it was issued to. A confidential client still authenticates (section 4.3.1: "Confidential
/// clients MUST authenticate").
/// </summary>
public class RefreshWithoutClientIdTests(TestFactory factory) : TestBase(factory)
{
    private const string PublicClientId = "e2e-public-refresh";

    [Fact]
    public async Task A_public_clients_refresh_token_is_redeemed_without_client_id()
    {
        await using var host = Host();
        using var client = CreateClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        var refreshToken = await ObtainRefreshTokenAsync(client, discovery, PublicClientId, secret: null);

        using var response = await RefreshAsync(client, discovery, refreshToken, clientId: null, secret: null);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.True(response.StatusCode == HttpStatusCode.OK, body.ToJsonString());
        var accessToken = DecodeJwtPayload(body[TokenResponse.Parameters.AccessToken]!.GetValue<string>());
        Assert.Equal(PublicClientId, accessToken[IanaClaimTypes.ClientId]?.GetValue<string>());
    }

    /// <summary>
    /// A confidential client's refresh token names its client too, and still does not stand in for the client's
    /// authentication; an unreadable refresh token names no client at all. Both are answered as a request that
    /// authenticates no client, before any refresh token is spent.
    /// </summary>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public async Task A_refresh_token_naming_no_public_client_is_not_redeemed_without_client_authentication(
        bool confidentialClientsToken)
    {
        await using var host = Host();
        using var client = CreateClient(host);
        var discovery = await FetchDiscoveryAsync(client);
        var refreshToken = confidentialClientsToken
            ? (await ObtainConfidentialOfflineTokensAsync(client, discovery))
                [TokenResponse.Parameters.RefreshToken]!.GetValue<string>()
            : "not-a-refresh-token";

        using var response = await RefreshAsync(client, discovery, refreshToken, clientId: null, secret: null);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidClient, body[ErrorResponse.Parameters.Error]?.GetValue<string>());

        if (confidentialClientsToken)
        {
            using var authenticated = await RefreshAsync(
                client,
                discovery,
                refreshToken,
                TestConstants.ConfidentialClientId,
                TestConstants.ConfidentialClientSecret);
            Assert.Equal(HttpStatusCode.OK, authenticated.StatusCode);
        }
    }

    private static async Task<string> ObtainRefreshTokenAsync(
        HttpClient client, DiscoveryDocument discovery, string clientId, string? secret)
    {
        var (verifier, challenge) = GeneratePkcePair();
        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = $"{Scopes.OpenId} {Scopes.OfflineAccess}",
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        });

        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [ClientRequest.Parameters.ClientId] = clientId,
        };
        if (secret is not null)
            form[ClientRequest.Parameters.ClientSecret] = secret;

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, form);
        return tokens[TokenResponse.Parameters.RefreshToken]!.GetValue<string>();
    }

    private static Task<HttpResponseMessage> RefreshAsync(
        HttpClient client, DiscoveryDocument discovery, string refreshToken, string? clientId, string? secret)
    {
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
        };
        if (clientId is not null)
            form[ClientRequest.Parameters.ClientId] = clientId;
        if (secret is not null)
            form[ClientRequest.Parameters.ClientSecret] = secret;

        return FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form);
    }

    private static HttpClient CreateClient(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

    /// <summary>
    /// The shared host with a public client of the code and refresh token grants, its refresh tokens rotated as OAuth
    /// 2.1 section 4.3.1 has a public client's refresh tokens either rotated or sender-constrained.
    /// </summary>
    private WebApplicationFactory<Program> Host()
        => Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
            services.PostConfigure<TestTenantSettings>(tenant =>
            {
                tenant.Clients =
                [
                    ..tenant.Clients,
                    new ClientInfo(PublicClientId)
                    {
                        TokenEndpointAuthMethod = ClientAuthenticationMethods.None,
                        AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
                        PkceRequired = true,
                        RedirectUris = [new Uri(TestConstants.RedirectUri)],
                        OfflineAccess = OfflineAccess.Allowed,
                    },
                ];
            })));
}
