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
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof that the refresh_token grant runs every presented token through the real JWT
/// validation gate (<c>RefreshTokenGrantHandler</c> → <c>AuthServiceJwtValidator</c> → the real
/// signer) before it ever touches the token store: a tampered refresh token is rejected with
/// <c>invalid_grant</c> however it was mutated. Covers the RFC 8725 attack matrix on the refresh-token
/// path — alg-stripping (§3.1), payload tampering (§2.1), signature corruption, and segment-count
/// confusion (RFC 7515 §7.1) — which the handler's unit tests cannot exercise because they mock the
/// validator. Each test obtains its own genuine refresh token and only ever submits a mutated copy, so
/// the real token is never spent and no rotation/family state is disturbed.
/// </summary>
public class RefreshTokenTamperingTests(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// alg-stripping: rewrite the header 'alg' to 'none' and drop the signature. The auth-service
    /// validator requires signed tokens (its default options), so the downgraded token is rejected
    /// at the JWT gate and the grant fails with invalid_grant.
    /// </summary>
    [Fact]
    public async Task AlgStrippedToNone_RefreshToken_IsRejected()
    {
        var (client, discovery, refreshToken) = await ObtainGenuineRefreshTokenAsync();

        var parts = refreshToken.Split('.');
        var header = JsonNode.Parse(Encoding.UTF8.GetString(Base64UrlDecode(parts[0])))!.AsObject();
        header["alg"] = SigningAlgorithms.None;
        header.Remove(JwtClaimTypes.KeyId);
        var tampered = $"{Base64UrlEncode(header.ToJsonString())}.{parts[1]}.";

        await AssertRefreshRejectedAsync(client, discovery, tampered);
    }

    /// <summary>
    /// Payload tampering: rewrite the subject (a privilege-escalation attempt) but keep the original
    /// signature. The signature no longer covers the mutated payload, so verification fails and the
    /// grant is rejected with invalid_grant.
    /// </summary>
    [Fact]
    public async Task TamperedPayload_RefreshToken_IsRejected()
    {
        var (client, discovery, refreshToken) = await ObtainGenuineRefreshTokenAsync();

        var parts = refreshToken.Split('.');
        var payload = JsonNode.Parse(Encoding.UTF8.GetString(Base64UrlDecode(parts[1])))!.AsObject();
        payload[IanaClaimTypes.Sub] = "attacker";
        var tampered = $"{parts[0]}.{Base64UrlEncode(payload.ToJsonString())}.{parts[2]}";

        await AssertRefreshRejectedAsync(client, discovery, tampered);
    }

    /// <summary>
    /// Segment-count confusion: append a fourth segment to the genuine three-part JWS. The validator
    /// rejects the 4-part string as malformed rather than stripping the junk and trusting the prefix.
    /// </summary>
    [Fact]
    public async Task AppendedSegment_RefreshToken_IsRejected()
    {
        var (client, discovery, refreshToken) = await ObtainGenuineRefreshTokenAsync();

        await AssertRefreshRejectedAsync(client, discovery, refreshToken + ".injected");
    }

    /// <summary>
    /// Signature corruption: flip the final signature character so it no longer verifies. The grant is
    /// rejected with invalid_grant, proving the signature is actually checked on the refresh path.
    /// </summary>
    [Fact]
    public async Task CorruptedSignature_RefreshToken_IsRejected()
    {
        var (client, discovery, refreshToken) = await ObtainGenuineRefreshTokenAsync();

        var parts = refreshToken.Split('.');
        var signature = parts[2];
        var flipped = signature[^1] == 'A' ? 'B' : 'A';
        var tampered = $"{parts[0]}.{parts[1]}.{signature[..^1]}{flipped}";

        await AssertRefreshRejectedAsync(client, discovery, tampered);
    }

    /// <summary>
    /// Drives a plain auth-code flow with <c>offline_access</c> for the confidential client and returns
    /// the genuine refresh token together with the client and discovery document used to obtain it.
    /// </summary>
    private async Task<(HttpClient Client, DiscoveryDocument Discovery, string RefreshToken)> ObtainGenuineRefreshTokenAsync()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
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

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();
        return (client, discovery, refreshToken);
    }

    private static async Task AssertRefreshRejectedAsync(
        HttpClient client, DiscoveryDocument discovery, string refreshToken)
    {
        var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(raw)!.AsObject();
        Assert.Equal(ErrorCodes.InvalidGrant, body["error"]!.GetValue<string>());
    }

    private static string Base64UrlEncode(string value) =>
        Convert.ToBase64String(Encoding.UTF8.GetBytes(value)).TrimEnd('=').Replace('+', '-').Replace('/', '_');

    private static byte[] Base64UrlDecode(string input)
    {
        var padded = input.Replace('-', '+').Replace('_', '/');
        switch (padded.Length % 4)
        {
            case 2: padded += "=="; break;
            case 3: padded += "="; break;
        }
        return Convert.FromBase64String(padded);
    }
}
