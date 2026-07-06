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
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of the OAuth 2.0 Security BCP refresh-token rotation model (RFC 9700 Section 4.14.2)
/// against the real token endpoint and the real token registry: a replay of a superseded refresh token
/// revokes the entire token family, so the currently active token of the same authorization grant dies
/// with it. This is the reuse-detection behaviour that contains a stolen refresh token — a leaked token is
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
        var initial = await ObtainRefreshTokenAsync(client, discovery);
        var rt1 = initial[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        // A normal refresh rotates rt1 -> rt2: rt1 becomes superseded (marked Used) and rt2 is now the
        // legitimately active token of the family. This also proves rotation works end-to-end.
        var rotated = await RefreshAsync(client, discovery, rt1);
        var rotatedBody = await ReadJsonAsync(rotated);
        Assert.True(rotated.IsSuccessStatusCode, $"first refresh should rotate, got {(int)rotated.StatusCode}: {rotatedBody}");
        var rt2 = rotatedBody[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();
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

    /// <summary>
    /// Drives a plain (non-PAR) auth-code flow with <c>offline_access</c> for the confidential client and
    /// returns the token response, whose <c>refresh_token</c> is the first member of a fresh family.
    /// </summary>
    private static async Task<JsonObject> ObtainRefreshTokenAsync(HttpClient client, DiscoveryDocument discovery)
    {
        var (verifier, challenge) = GeneratePkcePair();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = $"{Scopes.OpenId} {Scopes.OfflineAccess}",
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        });

        return await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });
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

    private static async Task<JsonObject> ReadJsonAsync(HttpResponseMessage response) =>
        JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!.AsObject();

    private static async Task AssertInvalidGrantAsync(HttpResponseMessage response)
    {
        var body = await ReadJsonAsync(response);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.InvalidGrant, body["error"]!.GetValue<string>());
    }
}
