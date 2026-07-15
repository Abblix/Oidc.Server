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
using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// End-to-end proof of pairwise subject protection: for a pairwise client the access token carries the pairwise
/// pseudonym in <c>sub</c> (the exact value the id_token carries in a real host per RFC 9068 Section 2.2), the real
/// subject is never exposed in the client-visible token, and the server still recovers the real subject by opening
/// that reversible pseudonym itself to resolve the user at UserInfo - no separate protected claim is carried.
/// Enabled on an isolated host so the shared default suite is untouched.
/// </summary>
/// <remarks>
/// This E2E host stubs <c>IUserClaimsProvider</c> with a static provider that bypasses the id_token's pairwise
/// conversion, so the pseudonym is checked against the deterministically-computed value rather than the stubbed
/// id_token's <c>sub</c>. The access-token pseudonym is produced by the code under test independently of the
/// stubbed claims provider.
/// </remarks>
public class PairwiseProtectedSubjectTests(TestFactory factory) : TestBase(factory)
{
    private const string PairwiseClientId = "e2e-pairwise";
    private const string RealSubject = "e2e-subject";

    [Fact]
    public async Task PairwiseClient_AccessMatchesIdToken_HidesRealSubject_AndUserInfoRecoversUser()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainPairwiseTokensAsync(client, discovery, Scopes.OpenId);
        var accessToken = tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        var accessPayload = DecodeJwtPayload(accessToken);
        var accessSub = accessPayload["sub"]!.GetValue<string>();

        // The access token carries the pairwise pseudonym - the exact value the id_token carries in a real host -
        // not the real subject: an unencrypted access token no longer leaks the real subject to the client. The
        // expected value is recomputed with the same salt and client so the check is deterministic.
        Assert.Equal(ExpectedPseudonym(), accessSub);
        Assert.NotEqual(RealSubject, accessSub);

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
        var accessSub = accessPayload["sub"]!.GetValue<string>();

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

    // The pairwise pseudonym the code under test must produce for this client and subject, recomputed with the same
    // salt and client so E2E checks are deterministic (the E2E host stubs the id_token's own pairwise conversion).
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
            AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken],
            PkceRequired = true,
            RedirectUris = [new Uri(TestConstants.RedirectUri, UriKind.Absolute)],
            OfflineAccessAllowed = true,
            SubjectType = SubjectTypes.Pairwise,
        };

        return Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {
                services.AddPairwiseSubjectIdentifiers(
                    new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) });

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
