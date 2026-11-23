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
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ResponseMembers = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// The revocation and introspection endpoints act on a token only for the client it belongs to, and decide that
/// before anything recorded about the token is read: reading the records of a superseded refresh token revokes its
/// whole grant, so a client presenting another client's token must not get that far.
/// </summary>
/// <remarks>
/// The other client here is a confidential client of the same host with no permission to introspect tokens of
/// others, so it is turned away by ownership alone.
/// </remarks>
public class TokenOwnershipTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>The client that presents tokens which are not its own.</summary>
    private const string OtherClientId = TestConstants.EmptyAllowlistClientId;

    /// <summary>
    /// A client that exchanges tokens and may not present those of others: the token exchange grant is the one place
    /// the token endpoint reads a token another client was issued.
    /// </summary>
    private const string ExchangingClientId = TestConstants.UnrestrictedClientId;

    [Fact]
    public async Task Another_client_revoking_a_superseded_refresh_token_leaves_the_owners_grant()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (superseded, active, accessToken) = await RotatedGrantAsync(client, discovery);

        var revocation = await RevokeAsync(client, discovery, superseded, OtherClientId);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);

        Assert.Equal(HttpStatusCode.OK, (await SendUserInfoAsync(client, discovery, accessToken)).StatusCode);
        Assert.True((await RefreshAsync(client, discovery, active)).IsSuccessStatusCode, "The owner's grant was revoked.");
    }

    [Fact]
    public async Task The_owner_revoking_its_superseded_refresh_token_still_revokes_the_grant()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (superseded, active, accessToken) = await RotatedGrantAsync(client, discovery);

        var revocation = await RevokeAsync(client, discovery, superseded, TestConstants.ConfidentialClientId);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);

        Assert.Equal(HttpStatusCode.Unauthorized, (await SendUserInfoAsync(client, discovery, accessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, (await RefreshAsync(client, discovery, active)).StatusCode);
    }

    [Fact]
    public async Task Another_client_introspecting_a_superseded_refresh_token_learns_nothing_and_leaves_the_grant()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (superseded, active, _) = await RotatedGrantAsync(client, discovery);

        var introspection = await IntrospectAsync(client, discovery, superseded, OtherClientId);
        Assert.False(introspection[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());

        Assert.True((await RefreshAsync(client, discovery, active)).IsSuccessStatusCode, "The owner's grant was revoked.");
    }

    /// <summary>
    /// Token exchange reads a refresh token presented as the subject or the actor the same way, so another client
    /// presenting a superseded one is refused and the owner's grant stays.
    /// </summary>
    [Theory]
    [InlineData(TokenRequest.Parameters.SubjectToken, TokenRequest.Parameters.SubjectTokenType)]
    [InlineData(TokenRequest.Parameters.ActorToken, TokenRequest.Parameters.ActorTokenType)]
    public async Task Another_client_exchanging_a_superseded_refresh_token_leaves_the_owners_grant(
        string tokenParameter,
        string typeParameter)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (superseded, active, _) = await RotatedGrantAsync(client, discovery);

        // The other client's own access token is the subject where the refresh token is the actor
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.TokenExchange,
            [TokenRequest.Parameters.SubjectToken] = superseded,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.RefreshToken,
            [ClientRequest.Parameters.ClientId] = ExchangingClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        };
        if (tokenParameter == TokenRequest.Parameters.ActorToken)
        {
            form[TokenRequest.Parameters.SubjectToken] = await ObtainAccessTokenAsync(
                client, discovery, ExchangingClientId, TestConstants.ConfidentialClientSecret);
            form[TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.AccessToken;
        }

        form[tokenParameter] = superseded;
        form[typeParameter] = TokenExchangeTokenTypes.RefreshToken;
        var exchange = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form);
        Assert.Equal(HttpStatusCode.BadRequest, exchange.StatusCode);

        Assert.True((await RefreshAsync(client, discovery, active)).IsSuccessStatusCode, "The owner's grant was revoked.");
    }

    [Fact]
    public async Task Another_client_introspecting_a_registration_access_token_finds_it_inactive()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var registered = await RegisterClientAsync(client, discovery, NewClientMetadata());
        var accessToken = registered[ResponseMembers.RegistrationAccessToken]!.GetValue<string>();

        var introspection = await IntrospectAsync(client, discovery, accessToken, OtherClientId);

        Assert.False(introspection[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());
    }

    [Fact]
    public async Task No_client_revokes_an_initial_access_token()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var tenant = TestTenant.Of(Factory.Services);
        var issued = await Factory.Services.GetRequiredService<IInitialAccessTokenService>().IssueTokenAsync(
            tenant,
            "registration-portal",
            Factory.Services.GetRequiredService<TimeProvider>().GetUtcNow(),
            TimeSpan.FromMinutes(5));

        var revocation = await RevokeAsync(client, discovery, issued.EncodedJwt, TestConstants.ConfidentialClientId);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);

        var status = await Factory.Services.GetRequiredService<ITokenRegistry>()
            .GetStatusAsync(tenant, issued.Token.Payload.JwtId!);
        Assert.Equal(JsonWebTokenStatus.Unknown, status);
    }

    /// <summary>
    /// A grant whose first refresh token was rotated: the superseded token, the active one, and an access token of
    /// the grant.
    /// </summary>
    private static async Task<(string Superseded, string Active, string AccessToken)> RotatedGrantAsync(
        HttpClient client, DiscoveryDocument discovery)
    {
        var initial = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var superseded = initial[TokenResponse.Parameters.RefreshToken]!.GetValue<string>();

        var rotation = await RefreshAsync(client, discovery, superseded);
        var rotated = await ReadJsonAsync(rotation);
        Assert.True(rotation.IsSuccessStatusCode, $"refresh should rotate, got {(int)rotation.StatusCode}: {rotated}");

        return (
            superseded,
            rotated[TokenResponse.Parameters.RefreshToken]!.GetValue<string>(),
            rotated[TokenResponse.Parameters.AccessToken]!.GetValue<string>());
    }

    private static JsonObject NewClientMetadata() => new()
    {
        [ClientRegistrationRequest.Parameters.RedirectUris] = new JsonArray(TestConstants.RedirectUri),
    };

    private static async Task<HttpResponseMessage> SendUserInfoAsync(
        HttpClient client, DiscoveryDocument discovery, string accessToken)
    {
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();
}
