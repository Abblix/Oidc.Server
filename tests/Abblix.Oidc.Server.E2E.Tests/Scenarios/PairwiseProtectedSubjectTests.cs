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
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using Xunit;
using Abblix.Jwt;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of pairwise subject protection: for a pairwise client the access token carries the pairwise
/// pseudonym in <c>sub</c> (the exact value the id_token carries in a real host per RFC 9068 Section 2.2), the real
/// subject is never exposed in the client-visible token, and the server still recovers the real subject by opening
/// that reversible pseudonym itself to resolve the user at UserInfo - no separate protected claim is carried.
/// Enabled on an isolated host so the shared default suite is untouched.
/// </summary>
/// <remarks>
/// The E2E host replaces the default claims stub (which writes the raw subject) with one that applies the pairwise
/// conversion exactly as the production <c>UserClaimsProvider</c> does, so the id_token carries the real per-sector
/// pseudonym. The test asserts <c>access_token.sub == id_token.sub</c> directly, and also against the
/// deterministically recomputed pseudonym to pin the exact value. The access-token pseudonym is produced by the
/// code under test (the token service), independent of the claims provider.
/// </remarks>
public class PairwiseProtectedSubjectTests(TestFactory factory) : TestBase(factory)
{
    private const string PairwiseClientId = "e2e-pairwise";
    private const string RealSubject = "e2e-subject";
    private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";

    [Fact]
    public async Task PairwiseClient_AccessMatchesIdToken_HidesRealSubject_AndUserInfoRecoversUser()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainPairwiseTokensAsync(client, discovery, Scopes.OpenId);
        var accessToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        var accessSub = DecodeJwtPayload(accessToken)[IanaClaimTypes.Sub]!.GetValue<string>();
        var idSub = DecodeJwtPayload(tokens[ResponseParameters.IdToken]!.GetValue<string>())[IanaClaimTypes.Sub]!.GetValue<string>();

        // RFC 9068 Section 2.2: the access token's sub matches the id_token's sub. Both carry the pairwise
        // pseudonym now that the access token's subject is sealed too - before #256 they diverged (real sub in the
        // access token, pairwise in the id_token). Asserting them equal proves the consistency directly, and the
        // recomputed value pins that it is the expected per-sector pseudonym, not the real subject.
        Assert.Equal(idSub, accessSub);
        Assert.Equal(ExpectedPseudonym(), accessSub);
        Assert.NotEqual(RealSubject, accessSub);
        Assert.NotEqual(RealSubject, idSub);

        // The server recovers the real subject by opening the reversible pseudonym in sub to resolve the user at
        // UserInfo - the real subject never appears in the client-visible token.
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.True(
            response.IsSuccessStatusCode,
            $"/userinfo rejected the pairwise access token: {(int)response.StatusCode} " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task PairwiseClient_Refresh_RecoversRealSubject_AndReissuesPseudonym()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainPairwiseTokensAsync(
            client, discovery, Scopes.OpenId, Scopes.OfflineAccess);
        var refreshToken = tokens[TokenRequest.Parameters.RefreshToken]!.GetValue<string>();

        // Refreshing forces the server to recover the real subject by opening the refresh token's pairwise sub
        // (AuthorizeByRefreshTokenAsync) and re-issue against it.
        var refreshed = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
            [AuthorizationRequest.Parameters.ClientId] = PairwiseClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var accessToken = refreshed[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var accessPayload = DecodeJwtPayload(accessToken);
        var accessSub = accessPayload[IanaClaimTypes.Sub]!.GetValue<string>();

        // The re-issued access token still carries the same pairwise pseudonym (not the real subject): refresh
        // opened the pseudonym to recover the real subject correctly, then re-sealed it to the same value.
        Assert.Equal(ExpectedPseudonym(), accessSub);
        Assert.NotEqual(RealSubject, accessSub);

        // The refreshed access token resolves the real user at UserInfo, proving refresh recovery end to end.
        using var request = new HttpRequestMessage(HttpMethod.Get, discovery.UserInfoEndpoint);
        request.Headers.Authorization = new AuthenticationHeaderValue(TokenTypes.Bearer, accessToken);
        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);

        Assert.True(
            response.IsSuccessStatusCode,
            $"/userinfo rejected the refreshed pairwise access token: {(int)response.StatusCode} " +
            await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task PairwiseClient_TokenExchange_OpensSubjectToken_AndReissuesPseudonym()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainPairwiseTokensAsync(client, discovery, Scopes.OpenId);
        var subjectToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        // Presenting the pairwise access token as an RFC 8693 subject_token forces the resolver to look the
        // pairwise client up and open the pseudonym in its sub back to the real subject before building the grant.
        var exchanged = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.TokenExchange,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            [AuthorizationRequest.Parameters.ClientId] = PairwiseClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var exchangedToken = exchanged[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var exchangedSub = DecodeJwtPayload(exchangedToken)[IanaClaimTypes.Sub]!.GetValue<string>();

        // The re-issued token carries the same pairwise pseudonym: the exchange recovered the real subject from the
        // presented pseudonym and re-sealed it for the same client. Had recovery not fired, the pseudonym would have
        // been treated as the real subject and sealed a second time into a different value - so this equality is
        // exactly what proves the subject_token was opened end to end.
        Assert.Equal(ExpectedPseudonym(), exchangedSub);
        Assert.NotEqual(RealSubject, exchangedSub);
    }

    // The pairwise pseudonym the code under test must produce for this client and subject, recomputed with the same
    // salt and client so the E2E can pin the exact expected value deterministically.
    private static string ExpectedPseudonym()
        => new SubjectTypeConverter(new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) })
            .Convert(RealSubject, new ClientInfo(PairwiseClientId)
            {
                SubjectType = SubjectTypes.Pairwise,
                RedirectUris = [new Uri(TestConstants.RedirectUri, UriKind.Absolute)],
            });

    private static async Task<JsonObject> ObtainPairwiseTokensAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        params string[] scope)
    {
        var (verifier, challenge) = GeneratePkcePair();

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, new ()
        {
            [AuthorizationRequest.Parameters.ClientId] = PairwiseClientId,
            [AuthorizationRequest.Parameters.ResponseType] = ResponseTypes.Code,
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = string.Join(" ", scope),
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
            [AuthorizationRequest.Parameters.ClientId] = PairwiseClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });
    }

    /// <summary>
    /// Builds an isolated host that enables pairwise identifiers, keeps the service tokens as signed JWS (so the test
    /// can decode <c>sub</c>) and registers a pairwise client alongside the pre-seeded ones. The reversible pairwise
    /// seal is keyed by the pairwise salt, so no service encryption key is needed. The shared default host stays
    /// untouched.
    /// </summary>
    /// <summary>
    /// RFC 7662 Section 5 offers two ways to keep an introspection response from disclosing a user to an
    /// unintended party. Withholding the identifier is the one it calls simplest; the other is to "transmit
    /// user identifiers as opaque service-specific strings, potentially returning different identifiers to
    /// each protected resource". A pairwise caller gets the second: a usable handle on the user that is its
    /// own, tells it nothing about the real subject, and cannot be matched against what another resource sees.
    /// </summary>
    [Fact]
    public async Task PairwiseIntrospector_ReceivesItsOwnPseudonym_NotTheRealSubject()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        // A token belonging to somebody else. Its owner is a public client, so it carries the real subject -
        // which is exactly what must not come back out of introspection.
        var tokens = await ObtainConfidentialOfflineTokensAsync(client, discovery);
        var accessToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        Assert.Equal(RealSubject, DecodeJwtPayload(accessToken)[IanaClaimTypes.Sub]!.GetValue<string>());

        var body = await IntrospectAsync(client, discovery, accessToken, PairwiseClientId);

        Assert.True(
            body[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>(),
            $"the protected resource was told a live token does not exist: {body.ToJsonString()}");

        var reported = body[IanaClaimTypes.Sub]?.GetValue<string>();
        Assert.NotEqual(RealSubject, reported);
        Assert.Equal(ExpectedPseudonym(), reported);
    }

    private static async Task<JsonObject> IntrospectAsync(
        HttpClient client, DiscoveryDocument discovery, string token, string callerClientId)
    {
        Assert.NotNull(discovery.IntrospectionEndpoint);
        using var request = new HttpRequestMessage(HttpMethod.Post, discovery.IntrospectionEndpoint);
        request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = callerClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [IntrospectionRequest.Parameters.Token] = token,
            [IntrospectionRequest.Parameters.TokenTypeHint] = UserInfoRequest.Parameters.AccessToken,
        });

        var response = await client.SendAsync(request, TestContext.Current.CancellationToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"introspect failed: {(int)response.StatusCode} {raw}");

        var body = JsonNode.Parse(raw)?.AsObject();
        Assert.NotNull(body);
        return body;
    }

    private WebApplicationFactory<Program> CreateHost()
    {
        var secret = new ClientSecret
        {
            Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(TestConstants.ConfidentialClientSecret)),
        };
        var pairwiseClient = new ClientInfo(PairwiseClientId)
        {
            ClientSecrets = [secret],
            TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
            AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken, GrantTypes.TokenExchange],
            PkceRequired = true,
            RedirectUris = [new Uri(TestConstants.RedirectUri, UriKind.Absolute)],
            OfflineAccessAllowed = true,
            SubjectType = SubjectTypes.Pairwise,

            // Also acts as a protected resource in the introspection scenario below, so it receives tokens
            // issued to other clients - and, being pairwise, sees their users under its own pseudonyms.
            AllowCrossClientIntrospection = true,
        };

        return Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.AddPairwiseSubjectIdentifiers(
                    new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) });

                // Emit a real pairwise id_token: the default host stub writes the raw subject to the id_token's
                // 'sub', so replace it with a provider that applies the pairwise conversion exactly as the
                // production UserClaimsProvider does. This lets the test assert access_token.sub == id_token.sub
                // (RFC 9068 Section 2.2) directly instead of against a recomputed value.
                services.Replace(
                    ServiceDescriptor.Singleton<IUserClaimsProvider, PairwiseStaticUserClaimsProvider>());

                services.AddSingleton<IPostConfigureOptions<OidcOptions>>(_ =>
                    new PostConfigureOptions<OidcOptions>(
                        Options.DefaultName,
                        options =>
                        {
                            // Keep tokens signed-only so the test can decode sub; the reversible pairwise seal is
                            // independent of service-token encryption (it is keyed by the pairwise salt).
                            options.ServiceTokens.AccessToken.Encrypt = false;
                            options.ServiceTokens.RefreshToken.Encrypt = false;
                            options.Clients = [.. options.Clients, pairwiseClient];
                        }));
            }));
    }

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
}
