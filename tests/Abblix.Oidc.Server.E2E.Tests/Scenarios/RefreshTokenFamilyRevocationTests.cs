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
using Abblix.Oidc.Server.Model;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of the OAuth 2.0 Security BCP refresh-token rotation model (RFC 9700 Section 4.14.2)
/// against the real token endpoint and the real token registry: a replay of a superseded refresh token
/// revokes the entire token family, so the currently active token of the same authorization grant dies
/// with it. This is the reuse-detection behavior that contains a stolen refresh token - a leaked token is
/// directly replayable for a public client, which is exactly why RFC 9700 Section 2.2.2 mandates rotation
/// there. The mechanism is client-type independent; the confidential client is used here as the most
/// heavily-exercised transport path.
/// </summary>
public class RefreshTokenFamilyRevocationTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task Replayed_superseded_refresh_token_revokes_the_whole_family()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        // A legitimate auth-code flow with offline_access issues the first refresh token of a new family
        // (rt1). The test client does not set AllowReuse, so it rotates by default (the secure default).
        var initial = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var rt1 = initial[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        // A normal refresh rotates rt1 -> rt2: rt1 becomes superseded (marked Used) and rt2 is now the
        // legitimately active token of the family. This also proves rotation works end-to-end.
        var rt2 = await RotateAsync(client, discovery, rt1);
        Assert.NotEqual(rt1, rt2); // rotation actually minted a new token

        // THEFT: the stolen rt1 is replayed after it was rotated. The AS cannot tell an attacker from a
        // lagging client, so it rejects the reuse AND revokes the whole family (RFC 9700 Section 4.14.2).
        var replay = await RefreshAsync(client, discovery, rt1);
        await AssertInvalidGrantAsync(replay);

        // FAMILY CASCADE: rt2 was valid a moment ago, but the reuse of its sibling revoked the lineage, so
        // rt2 is now rejected too. The active token an attacker would be holding dies with the family.
        var afterCascade = await RefreshAsync(client, discovery, rt2);
        await AssertInvalidGrantAsync(afterCascade);
    }

    [Fact]
    public async Task Replaying_the_oldest_token_revokes_a_multi_generation_family()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        // Build a three-generation lineage rt1 -> rt2 -> rt3. Each rotation supersedes its predecessor and
        // carries the same grant_id forward, so rt1, rt2 and rt3 all belong to one family; rt3 is active.
        var initial = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var rt1 = initial[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();
        var rt2 = await RotateAsync(client, discovery, rt1);
        var rt3 = await RotateAsync(client, discovery, rt2);
        Assert.NotEqual(rt1, rt2);
        Assert.NotEqual(rt2, rt3);
        Assert.NotEqual(rt1, rt3);

        // Replaying rt1 - superseded two generations ago - is still the breach signal that revokes the whole
        // family, not merely the token replayed (RFC 9700 Section 4.14.2).
        await AssertInvalidGrantAsync(await RefreshAsync(client, discovery, rt1));

        // Every member of the lineage is now dead: the already-superseded rt2 and, crucially, the still-active
        // rt3 - the token an attacker who had rotated forward would be holding.
        await AssertInvalidGrantAsync(await RefreshAsync(client, discovery, rt2));
        await AssertInvalidGrantAsync(await RefreshAsync(client, discovery, rt3));
    }

    [Fact]
    public async Task Revoking_the_family_also_refuses_its_access_tokens()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        // The first access token is issued together with rt1, the second one at the rotation that replaces it,
        // so between them they cover both ways the token endpoint issues an access token of this grant.
        var initial = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var rt1 = initial[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();
        var firstAccessToken = initial[ResponseParameters.AccessToken]!.GetValue<string>();

        var rotation = await RefreshAsync(client, discovery, rt1);
        var rotated = await ReadJsonAsync(rotation);
        Assert.True(rotation.IsSuccessStatusCode, $"refresh should rotate, got {(int)rotation.StatusCode}: {rotated}");
        var rotatedAccessToken = rotated[ResponseParameters.AccessToken]!.GetValue<string>();

        // Both are accepted before the family is revoked, so a refusal below is the revocation speaking and not
        // a token UserInfo would have refused anyway.
        Assert.Equal(HttpStatusCode.OK, (await SendUserInfoAsync(client, discovery, firstAccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.OK, (await SendUserInfoAsync(client, discovery, rotatedAccessToken)).StatusCode);

        await AssertInvalidGrantAsync(await RefreshAsync(client, discovery, rt1));

        Assert.Equal(HttpStatusCode.Unauthorized, (await SendUserInfoAsync(client, discovery, firstAccessToken)).StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, (await SendUserInfoAsync(client, discovery, rotatedAccessToken)).StatusCode);
    }

    private static async Task<HttpResponseMessage> SendUserInfoAsync(
        HttpClient client, DiscoveryDocument discovery, string accessToken)
    {
        Assert.NotNull(discovery.UserInfoEndpoint);
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        return await client.SendAsync(request, TestContext.Current.CancellationToken);
    }

    private static async Task<HttpResponseMessage> RefreshAsync(
        HttpClient client, DiscoveryDocument discovery, string refreshToken) =>
        await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

    /// <summary>
    /// Refreshes with <paramref name="refreshToken"/>, asserts the rotation succeeded, and returns the newly
    /// issued refresh token - the next member of the same grant family.
    /// </summary>
    private static async Task<string> RotateAsync(HttpClient client, DiscoveryDocument discovery, string refreshToken)
    {
        var response = await RefreshAsync(client, discovery, refreshToken);
        var body = await ReadJsonAsync(response);
        Assert.True(response.IsSuccessStatusCode, $"refresh should rotate, got {(int)response.StatusCode}: {body}");
        return body[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();
    }

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    private static async Task AssertInvalidGrantAsync(HttpResponseMessage response)
    {
        var body = await ReadJsonAsync(response);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidGrant, body[ResponseParameters.Error]!.GetValue<string>());
    }
}
