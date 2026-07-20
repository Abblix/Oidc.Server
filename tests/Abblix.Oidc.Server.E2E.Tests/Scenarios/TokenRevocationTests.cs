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

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of the token revocation endpoint (RFC 7009) against the real endpoint and the real token
/// registry.
/// </summary>
/// <remarks>
/// Revocation is the control an operator or a user reaches for after a device is lost or a token leaks, so the
/// property that matters is not the shape of the response but whether the token stops working afterwards. A
/// revocation endpoint that answers 200 and leaves the token usable is worse than none at all: it reports that
/// the danger has been dealt with.
///
/// The suite previously exercised revocation only as a side effect of reuse detection, which revokes a family
/// on its own initiative. Nothing walked the endpoint a client actually calls.
/// </remarks>
public class TokenRevocationTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task A_revoked_refresh_token_can_no_longer_be_redeemed()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        // Proving it works first: otherwise a test that only checks the token fails afterwards would pass
        // just as happily against a token that never worked at all.
        var beforeRevocation = await RefreshAsync(client, discovery, refreshToken);
        Assert.True(beforeRevocation.IsSuccessStatusCode);
        var rotated = (await ReadJsonAsync(beforeRevocation))[TokenRequest.Parameters.RefreshToken]!
            .GetValue<string>();

        var revocation = await RevokeAsync(client, discovery, rotated);
        Assert.Equal(HttpStatusCode.OK, revocation.StatusCode);

        var afterRevocation = await RefreshAsync(client, discovery, rotated);
        await AssertInvalidGrantAsync(afterRevocation);
    }

    [Fact]
    public async Task Revoking_a_token_that_was_never_issued_still_answers_success()
    {
        // RFC 7009 Section 2.2 requires 200 for a token the server does not recognise. The reason is not
        // politeness: a distinguishable answer turns the endpoint into an oracle that tells an attacker
        // whether a guessed token exists, which is the one thing this endpoint must never reveal.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var response = await RevokeAsync(client, discovery, "a-token-this-server-never-issued");

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
    }

    [Fact]
    public async Task Revocation_requires_the_client_to_authenticate()
    {
        // Without client authentication anyone holding a token could revoke it, and anyone able to guess one
        // could try. That turns a security control into a denial-of-service lever against other clients.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.RevocationEndpoint!,
            new Dictionary<string, string> { ["token"] = refreshToken });

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);

        // The token survives the unauthenticated attempt, which is the half that matters: a rejected request
        // that revoked anyway would be the denial of service this check exists to prevent.
        var stillWorks = await RefreshAsync(client, discovery, refreshToken);
        Assert.True(stillWorks.IsSuccessStatusCode);
    }

    [Fact]
    public async Task The_revocation_endpoint_is_published_in_discovery()
    {
        // A client finds this endpoint through discovery, so an endpoint that is enabled but unadvertised is
        // unreachable in practice.
        var discovery = await FetchDiscoveryAsync(CreateClient());

        Assert.NotNull(discovery.RevocationEndpoint);
    }

    private static async Task<HttpResponseMessage> RevokeAsync(
        HttpClient client, DiscoveryDocument discovery, string token) =>
        await FormPostHelpers.PostFormAsync(client, discovery.RevocationEndpoint!, new Dictionary<string, string>
        {
            ["token"] = token,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

    private static async Task<HttpResponseMessage> RefreshAsync(
        HttpClient client, DiscoveryDocument discovery, string refreshToken) =>
        await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    private static async Task AssertInvalidGrantAsync(HttpResponseMessage response)
    {
        var body = await ReadJsonAsync(response);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidGrant, body["error"]!.GetValue<string>());
    }
}
