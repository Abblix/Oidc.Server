// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    private const string OtherSectorClientId = "e2e-pairwise-other-sector";
    private const string OtherSector = "other-sector.example.com";
    private const string RealSubject = "e2e-subject";

    [Fact]
    public async Task PairwiseClient_AccessMatchesIdToken_HidesRealSubject_AndUserInfoRecoversUser()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ObtainPairwiseTokensAsync(client, discovery, Scopes.OpenId);
        var accessToken = tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>();

        var accessSub = DecodeJwtPayload(accessToken)[IanaClaimTypes.Sub]!.GetValue<string>();
        var idSub = DecodeJwtPayload(tokens[TokenResponse.Parameters.IdToken]!.GetValue<string>())[IanaClaimTypes.Sub]!.GetValue<string>();

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
        var refreshToken = tokens[TokenResponse.Parameters.RefreshToken]!.GetValue<string>();

        // Refreshing forces the server to recover the real subject by opening the refresh token's pairwise sub
        // (AuthorizeByRefreshTokenAsync) and re-issue against it.
        var refreshed = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [TokenRequest.Parameters.RefreshToken] = refreshToken,
            [ClientRequest.Parameters.ClientId] = PairwiseClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var accessToken = refreshed[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
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
        var subjectToken = tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>();

        // Presenting the pairwise access token as an RFC 8693 subject_token forces the resolver to look the
        // pairwise client up and open the pseudonym in its sub back to the real subject before building the grant.
        var exchanged = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.TokenExchange,
            [TokenRequest.Parameters.SubjectToken] = subjectToken,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.AccessToken,
            [ClientRequest.Parameters.ClientId] = PairwiseClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var exchangedToken = exchanged[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
        var exchangedSub = DecodeJwtPayload(exchangedToken)[IanaClaimTypes.Sub]!.GetValue<string>();

        // The re-issued token carries the same pairwise pseudonym: the exchange recovered the real subject from the
        // presented pseudonym and re-sealed it for the same client. Had recovery not fired, the pseudonym would have
        // been treated as the real subject and sealed a second time into a different value - so this equality is
        // exactly what proves the subject_token was opened end to end.
        Assert.Equal(ExpectedPseudonym(), exchangedSub);
        Assert.NotEqual(RealSubject, exchangedSub);
    }

    /// <summary>
    /// A pairwise client sees the actor of a delegated token under its own pseudonym, as it sees the subject, and a
    /// delegated token exchanged again keeps that same pseudonym: the server opened the actor before sealing it anew.
    /// </summary>
    [Fact]
    public async Task PairwiseClient_Delegation_SealsTheActorForItsSector_AndAReexchangeKeepsIt()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var subjectToken = await PairwiseAccessTokenAsync(client, discovery);
        var actorToken = await PairwiseAccessTokenAsync(client, discovery);
        var delegated = await ExchangeAsync(client, discovery, PairwiseClientId, subjectToken, actorToken);

        Assert.Equal(ExpectedPseudonym(), ActorSubjectOf(delegated));

        var reexchanged = await ExchangeAsync(client, discovery, PairwiseClientId, delegated, actorToken: null);

        Assert.Equal(ExpectedPseudonym(), ActorSubjectOf(reexchanged));
    }

    /// <summary>
    /// A delegated token issued to one pairwise client and exchanged by another of a different sector carries its
    /// actor opened under the sector of the client it was issued to and sealed under the sector of the client that
    /// receives the new token.
    /// </summary>
    [Fact]
    public async Task ACrossClientExchange_ReSealsTheActorForTheReceivingClientsSector()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var subjectToken = await PairwiseAccessTokenAsync(client, discovery);
        var actorToken = await PairwiseAccessTokenAsync(client, discovery);
        var delegated = await ExchangeAsync(client, discovery, PairwiseClientId, subjectToken, actorToken);

        var exchanged = await ExchangeAsync(client, discovery, OtherSectorClientId, delegated, actorToken: null);

        Assert.Equal(ExpectedPseudonym(OtherSectorClient()), ActorSubjectOf(exchanged));
        Assert.NotEqual(ExpectedPseudonym(), ActorSubjectOf(exchanged));
    }

    /// <summary>
    /// An actor_token of a public-subject client names the real party, and the pairwise client receiving the
    /// delegated token sees that party under its own pseudonym.
    /// </summary>
    [Fact]
    public async Task APublicClientsActor_IsSealedForThePairwiseRecipient()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var subjectToken = await PairwiseAccessTokenAsync(client, discovery);
        var actorToken = (await ObtainConfidentialOfflineTokensAsync(client, discovery))
            [TokenResponse.Parameters.AccessToken]!.GetValue<string>();
        Assert.Equal(RealSubject, DecodeJwtPayload(actorToken)[IanaClaimTypes.Sub]!.GetValue<string>());

        var delegated = await ExchangeAsync(client, discovery, PairwiseClientId, subjectToken, actorToken);

        Assert.Equal(ExpectedPseudonym(), ActorSubjectOf(delegated));
    }

    /// <summary>
    /// RFC 8693 section 4.1: act "has the same semantics and format" in an introspection response, so a protected
    /// resource asking about a delegated token learns who acts, under the identifier it is entitled to: the owner
    /// sees the pseudonym of its token, another pairwise caller its own.
    /// </summary>
    [Fact]
    public async Task Introspection_ShowsTheActorToEveryCaller_UnderItsOwnPseudonym()
    {
        await using var host = CreateHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var subjectToken = await PairwiseAccessTokenAsync(client, discovery);
        var actorToken = await PairwiseAccessTokenAsync(client, discovery);
        var delegated = await ExchangeAsync(client, discovery, PairwiseClientId, subjectToken, actorToken);

        var byOwner = await IntrospectAsync(client, discovery, delegated, PairwiseClientId);
        var byOther = await IntrospectAsync(client, discovery, delegated, OtherSectorClientId);

        Assert.Equal(ExpectedPseudonym(), byOwner[IanaClaimTypes.Act]?[IanaClaimTypes.Sub]?.GetValue<string>());
        Assert.Equal(
            ExpectedPseudonym(OtherSectorClient()),
            byOther[IanaClaimTypes.Act]?[IanaClaimTypes.Sub]?.GetValue<string>());
    }

    private static async Task<string> PairwiseAccessTokenAsync(HttpClient client, DiscoveryDocument discovery)
        => (await ObtainPairwiseTokensAsync(client, discovery, Scopes.OpenId))
            [TokenResponse.Parameters.AccessToken]!.GetValue<string>();

    private static async Task<string> ExchangeAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientId,
        string subjectToken,
        string? actorToken)
    {
        var form = new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.TokenExchange,
            [TokenRequest.Parameters.SubjectToken] = subjectToken,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.AccessToken,
            [ClientRequest.Parameters.ClientId] = clientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        };
        if (actorToken is not null)
        {
            form[TokenRequest.Parameters.ActorToken] = actorToken;
            form[TokenRequest.Parameters.ActorTokenType] = TokenExchangeTokenTypes.AccessToken;
        }

        var response = await ExchangeCodeForTokensAsync(client, discovery, form);
        return response[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
    }

    private static string? ActorSubjectOf(string token)
        => DecodeJwtPayload(token)[IanaClaimTypes.Act]?[IanaClaimTypes.Sub]?.GetValue<string>();

    // The pairwise pseudonym the code under test must produce for this client and subject, recomputed with the same
    // salt and client so the E2E can pin the exact expected value deterministically.
    private static string ExpectedPseudonym()
        => ExpectedPseudonym(new ClientInfo(PairwiseClientId)
        {
            SubjectType = SubjectTypes.Pairwise,
            RedirectUris = [new Uri(TestConstants.RedirectUri, UriKind.Absolute)],
        });

    private static string ExpectedPseudonym(ClientInfo client)
        => new SubjectTypeConverter(new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) })
            .Convert(RealSubject, client);

    /// <summary>
    /// A second pairwise client whose sector differs from the first one's, allowed to exchange and introspect tokens
    /// issued to other clients.
    /// </summary>
    private static ClientInfo OtherSectorClient() => new(OtherSectorClientId)
    {
        ClientSecrets = [ConfidentialSecret()],
        TokenEndpointAuthMethod = ClientAuthenticationMethods.ClientSecretPost,
        AllowedGrantTypes = [GrantTypes.TokenExchange],
        SubjectType = SubjectTypes.Pairwise,
        SectorIdentifier = OtherSector,
        AllowCrossClientSubjectTokenExchange = true,
        AllowCrossClientIntrospection = true,
    };

    private static ClientSecret ConfidentialSecret() => new()
    {
        Sha512Hash = SHA512.HashData(Encoding.UTF8.GetBytes(TestConstants.ConfidentialClientSecret)),
    };

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
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [ClientRequest.Parameters.ClientId] = PairwiseClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });
    }

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
        var accessToken = tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
        Assert.Equal(RealSubject, DecodeJwtPayload(accessToken)[IanaClaimTypes.Sub]!.GetValue<string>());

        var body = await IntrospectAsync(client, discovery, accessToken, PairwiseClientId);

        Assert.True(
            body[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>(),
            $"the protected resource was told a live token does not exist: {body.ToJsonString()}");

        var reported = body[IanaClaimTypes.Sub]?.GetValue<string>();
        Assert.NotEqual(RealSubject, reported);
        Assert.Equal(ExpectedPseudonym(), reported);
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
            AllowedGrantTypes = [GrantTypes.AuthorizationCode, GrantTypes.RefreshToken, GrantTypes.TokenExchange],
            PkceRequired = true,
            RedirectUris = [new Uri(TestConstants.RedirectUri, UriKind.Absolute)],
            OfflineAccess = OfflineAccess.Allowed,
            SubjectType = SubjectTypes.Pairwise,

            // Also acts as a protected resource in the introspection scenario below, so it receives tokens
            // issued to other clients - and, being pairwise, sees their users under its own pseudonyms.
            AllowCrossClientIntrospection = true,

            // Accepts an actor_token issued to another client in the delegation scenarios.
            AllowCrossClientSubjectTokenExchange = true,
        };

        return Factory.WithWebHostBuilder(builder =>
            builder.ConfigureTestServices(services =>
            {

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
                        }));

                services.PostConfigure<TestTenantSettings>(tenant =>
                {
                    tenant.PairwiseSubject = new PairwiseSubjectSettings { Salt = Convert.ToBase64String(new byte[32]) };
                    tenant.Clients = [.. tenant.Clients, pairwiseClient, OtherSectorClient()];
                });
            }));
    }

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
}
