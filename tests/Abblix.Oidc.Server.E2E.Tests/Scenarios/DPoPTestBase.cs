// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.Model;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// Shared driver/assert helpers for the RFC 9449 DPoP scenario classes. The DPoP
/// suite is split by RFC section into <see cref="DPoPTests"/> (token endpoint, §6),
/// <see cref="DPoPRefreshTests"/> (refresh-token rebinding, §5) and
/// <see cref="DPoPUserInfoTests"/> (resource access, §9) so each runs as its own
/// parallel xunit collection; this non-test base keeps the PAR -> /authorize ->
/// /token choreography and the <c>cnf.jkt</c> assertions in one place. Helpers are
/// <c>protected static</c> - section-specific helpers live on the concrete classes.
/// </summary>
public abstract class DPoPTestBase(TestFactory factory) : TestBase(factory)
{
    /// <summary>
    /// Drives PAR -> /authorize -> /token with optional DPoP proofs on PAR and token.
    /// Returns the parsed token response on the success path; throws on any non-success
    /// HTTP status -- callers expecting a token-endpoint error use the *ExpectingError*
    /// variant.
    /// </summary>
    protected static async Task<JsonObject> DriveParAuthorizeTokenAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string? parProof,
        string? tokenProof,
        string scope = Scopes.OpenId,
        string? clientSecret = TestConstants.ConfidentialClientSecret)
    {
        var (verifier, code) = await PerformParAndAuthorizeAsync(
            client, discovery, clientId, parProof, scope, clientSecret);

        var tokenResponse = await SendTokenAsync(client, discovery, clientId, code, verifier, tokenProof, clientSecret);
        Assert.True(tokenResponse.IsSuccessStatusCode,
            $"/token failed: {(int)tokenResponse.StatusCode} {await tokenResponse.Content.ReadAsStringAsync()}");
        return JsonNode.Parse(await tokenResponse.Content.ReadAsStringAsync())!.AsObject();
    }

    /// <summary>
    /// Same flow as <see cref="DriveParAuthorizeTokenAsync"/> but expects the /token
    /// call to fail; returns the error code from the response body. PAR and /authorize
    /// are still expected to succeed -- if they don't, the test fails loudly so the
    /// scenario doesn't silently green-pass on a wrong-stage rejection.
    /// </summary>
    protected static async Task<string> DriveParAuthorizeTokenExpectingErrorAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string? parProof,
        string? tokenProof)
    {
        var (verifier, code) = await PerformParAndAuthorizeAsync(
            client, discovery, clientId, parProof, Scopes.OpenId, TestConstants.ConfidentialClientSecret);

        var tokenResponse = await SendTokenAsync(client, discovery, clientId, code, verifier, tokenProof);
        Assert.False(tokenResponse.IsSuccessStatusCode,
            $"/token unexpectedly succeeded: {await tokenResponse.Content.ReadAsStringAsync()}");
        Assert.Equal(HttpStatusCode.BadRequest, tokenResponse.StatusCode);
        var body = JsonNode.Parse(await tokenResponse.Content.ReadAsStringAsync())!.AsObject();
        return body[ResponseParameters.Error]!.GetValue<string>();
    }

    /// <summary>
    /// Pushes a PAR request, retrieves the resulting <c>request_uri</c>, drives /authorize
    /// to consume it, and returns the issued auth code paired with the PKCE verifier so a
    /// caller can complete the flow at /token. Shared bootstrap for the success and
    /// expecting-error driver variants - keeps the PAR + /authorize choreography in one
    /// place even though the two callers diverge on /token-stage expectations.
    /// </summary>
    protected static async Task<(string Verifier, string Code)> PerformParAndAuthorizeAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string? parProof,
        string scope,
        string? clientSecret)
    {
        var (verifier, challenge) = GeneratePkcePair();

        var parResponse = await SendParAsync(client, discovery, clientId, challenge, parProof, scope, clientSecret);
        Assert.True(parResponse.IsSuccessStatusCode,
            $"PAR failed: {(int)parResponse.StatusCode} {await parResponse.Content.ReadAsStringAsync()}");
        var parBody = JsonNode.Parse(await parResponse.Content.ReadAsStringAsync())!.AsObject();
        var requestUri = parBody[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.RequestUri] = requestUri,
        });
        return (verifier, code);
    }

    protected static async Task<HttpResponseMessage> SendParAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string challenge,
        string? proofJwt,
        string scope = Scopes.OpenId,
        string? clientSecret = TestConstants.ConfidentialClientSecret)
    {
        var form = new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = clientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = scope,
            [AuthorizationRequest.Parameters.State] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.Nonce] = Guid.NewGuid().ToString("N"),
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
        };
        // Public clients (TokenEndpointAuthMethod = none) supply no client_secret.
        if (clientSecret is not null)
            form[ClientRequest.Parameters.ClientSecret] = clientSecret;
        return await FormPostHelpers.PostFormAsync(client, discovery.PushedAuthorizationRequestEndpoint!, form, proofJwt);
    }

    protected static async Task<HttpResponseMessage> SendTokenAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string code,
        string verifier,
        string? proofJwt,
        string? clientSecret = TestConstants.ConfidentialClientSecret)
    {
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [ClientRequest.Parameters.ClientId] = clientId,
        };
        if (clientSecret is not null)
            form[ClientRequest.Parameters.ClientSecret] = clientSecret;
        return await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form, proofJwt);
    }

    protected static void AssertDPoPBound(JsonObject tokenResponse, string expectedThumbprint)
    {
        var tokenType = tokenResponse[BackChannelTokenPushRequest.Parameters.TokenType]!.GetValue<string>();
        Assert.Equal(TokenTypes.DPoP, tokenType);

        // RFC 9449 §6: the issued access token carries cnf.jkt = the proof key's JWK thumbprint.
        var accessToken = tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var payload = DecodeJwtPayload(accessToken);

        var cnf = payload["cnf"]?.AsObject();
        Assert.NotNull(cnf);

        var jkt = cnf["jkt"]?.GetValue<string>();
        Assert.Equal(expectedThumbprint, jkt);
    }

    protected static void AssertBearer(JsonObject tokenResponse)
    {
        var tokenType = tokenResponse[BackChannelTokenPushRequest.Parameters.TokenType]!.GetValue<string>();
        Assert.Equal(TokenTypes.Bearer, tokenType);

        var accessToken = tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var payload = DecodeJwtPayload(accessToken);

        Assert.Null(payload["cnf"]);
    }
}
