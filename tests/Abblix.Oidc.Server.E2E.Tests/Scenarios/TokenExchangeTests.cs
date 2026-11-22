// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Microsoft.AspNetCore.Mvc.Testing;
using Xunit;
using Abblix.Jwt;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 8693 Token Exchange end-to-end against the test OIDC provider. Each test obtains a real
/// access token via the auth-code path first, then exercises the token-exchange grant at the
/// /token endpoint and asserts on the wire shape of the issued JWT.
/// </summary>
public class TokenExchangeTests(TestFactory factory) : TestBase(factory)
{
    private const string TokenExchangeGrantType = GrantTypes.TokenExchange;

    private const string PaymentInitiationWireJson =
        """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";

    [Fact]
    public async Task Impersonation_preserves_subject_and_forwards_authorization_details()
    {
        // 1. Mint an access token via the standard auth-code flow.
        var initial = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);
        var subjectToken = initial[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
        var originalSubject = DecodeJwtPayload(subjectToken)["sub"]!.GetValue<string>();

        // 2. Exchange it via grant_type=token-exchange.
        var exchanged = await PerformTokenExchangeAsync(new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = TokenExchangeGrantType,
            [TokenRequest.Parameters.SubjectToken] = subjectToken,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.AccessToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        // 3. Issued access token: same sub, AD forwarded byte-exact, no act claim.
        var newPayload = DecodeJwtPayload(exchanged[TokenResponse.Parameters.AccessToken]!.GetValue<string>());
        Assert.Equal(originalSubject, newPayload["sub"]!.GetValue<string>());
        var ad = newPayload[IanaClaimTypes.AuthorizationDetails] as JsonArray;
        Assert.NotNull(ad);
        Assert.Equal(PaymentInitiationWireJson, ad.ToJsonString());
        Assert.Null(newPayload["act"]);
    }

    /// <summary>
    /// RFC 8693 section 2.1 lists no redirect_uri, and RFC 6749 section 3.2 has the server "ignore unrecognized
    /// request parameters", so an exchange carrying one is served rather than refused for a redirect it never had.
    /// </summary>
    [Fact]
    public async Task A_redirect_uri_on_an_exchange_is_ignored()
    {
        var initial = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);
        var subjectToken = initial[TokenResponse.Parameters.AccessToken]!.GetValue<string>();

        var exchanged = await PerformTokenExchangeAsync(new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = TokenExchangeGrantType,
            [TokenRequest.Parameters.SubjectToken] = subjectToken,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.AccessToken,
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        Assert.NotNull(exchanged[TokenResponse.Parameters.AccessToken]);
    }

    /// <summary>
    /// A delegated token exchanged again without an actor_token keeps its act: RFC 8693 section 4.1 has act tell
    /// the resource server who acts for the subject, and dropping it would present the delegate as the user.
    /// </summary>
    [Fact]
    public async Task A_delegated_token_exchanged_without_an_actor_keeps_its_act()
    {
        var subjectToken = (await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson))[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
        var actorToken = (await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson))[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
        var actorSub = DecodeJwtPayload(actorToken)[IanaClaimTypes.Sub]!.GetValue<string>();

        var delegated = (await PerformTokenExchangeAsync(new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = TokenExchangeGrantType,
            [TokenRequest.Parameters.SubjectToken] = subjectToken,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.AccessToken,
            [TokenRequest.Parameters.ActorToken] = actorToken,
            [TokenRequest.Parameters.ActorTokenType] = TokenExchangeTokenTypes.AccessToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        }))[TokenResponse.Parameters.AccessToken]!.GetValue<string>();

        var exchanged = await PerformTokenExchangeAsync(new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = TokenExchangeGrantType,
            [TokenRequest.Parameters.SubjectToken] = delegated,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.AccessToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var act = DecodeJwtPayload(exchanged[TokenResponse.Parameters.AccessToken]!.GetValue<string>())[IanaClaimTypes.Act]
            as JsonObject;
        Assert.NotNull(act);
        Assert.Equal(actorSub, act[IanaClaimTypes.Sub]!.GetValue<string>());
        Assert.Null(act[IanaClaimTypes.Act]);
    }

    [Fact]
    public async Task Delegation_emits_act_claim_with_actor_subject()
    {
        // 1. Mint the subject_token (the principal acting through the actor).
        var subject = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);
        var subjectToken = subject[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
        var subjectSub = DecodeJwtPayload(subjectToken)["sub"]!.GetValue<string>();

        // 2. Mint the actor_token. Same client + flow stands in for a distinct service identity
        // -- the test exercises the act-chain wiring, not real cross-actor identity (TestHost has
        // a single auto-authenticated user).
        var actor = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);
        var actorToken = actor[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
        var actorSub = DecodeJwtPayload(actorToken)["sub"]!.GetValue<string>();

        // 3. Exchange with both subject_token and actor_token.
        var exchanged = await PerformTokenExchangeAsync(new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = TokenExchangeGrantType,
            [TokenRequest.Parameters.SubjectToken] = subjectToken,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.AccessToken,
            [TokenRequest.Parameters.ActorToken] = actorToken,
            [TokenRequest.Parameters.ActorTokenType] = TokenExchangeTokenTypes.AccessToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        // 4. Issued token: sub = subject, act = { sub: actor }.
        var newPayload = DecodeJwtPayload(exchanged[TokenResponse.Parameters.AccessToken]!.GetValue<string>());
        Assert.Equal(subjectSub, newPayload["sub"]!.GetValue<string>());
        var act = newPayload["act"] as JsonObject;
        Assert.NotNull(act);
        Assert.Equal(actorSub, act["sub"]!.GetValue<string>());
    }

    [Fact]
    public async Task Dynamic_client_registration_round_trips_token_exchange_subject_token_types_metadata()
    {
        // Non-standard DCR metadata: token_exchange_subject_token_types lets a host pin the
        // per-client allowlist of RFC 8693 subject_token_type URIs at registration time. The
        // registered value flows ClientInfo -> response echo, and at runtime the grant handler
        // enforces it via TokenExchangeAllowedSubjectTokenTypes tri-state semantics.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var requested = new JsonObject
        {
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
            [RegistrationMembers.GrantTypes] = new JsonArray { GrantTypes.AuthorizationCode },
            [RegistrationMembers.ResponseTypes] = new JsonArray { ResponseTypes.Code },
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
            [RegistrationMembers.TokenExchangeSubjectTokenTypes] = new JsonArray
            {
                TokenExchangeTokenTypes.AccessToken,
                TokenExchangeTokenTypes.IdToken,
            },
        };
        var registered = await RegisterClientAsync(client, discovery, requested);

        var echoed = registered[ClientRegistrationResponse.Parameters.TokenExchangeSubjectTokenTypes] as JsonArray;
        Assert.NotNull(echoed);
        Assert.Equal(2, echoed.Count);
        Assert.Equal(TokenExchangeTokenTypes.AccessToken, echoed[0]!.GetValue<string>());
        Assert.Equal(TokenExchangeTokenTypes.IdToken, echoed[1]!.GetValue<string>());
    }

    /// <summary>
    /// An actor_token is checked against a session revocation the same way a subject_token is, so an ID token naming
    /// no session is refused as the actor too, while the same exchange with an ID token that names its session goes
    /// through.
    /// </summary>
    [Theory]
    [InlineData(true, HttpStatusCode.OK)]
    [InlineData(false, HttpStatusCode.BadRequest)]
    public async Task An_actor_id_token_is_exchanged_only_when_it_names_its_session(
        bool clientUsesSessionAtLogout, HttpStatusCode expected)
    {
        await using var host = clientUsesSessionAtLogout ? Factory.WithSessionLogout() : Factory.WithWebHostBuilder(_ => { });
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var subject = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson, client: client);
        var actor = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson, client: client);

        using var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = TokenExchangeGrantType,
            [TokenRequest.Parameters.SubjectToken] = subject[TokenResponse.Parameters.AccessToken]!.GetValue<string>(),
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.AccessToken,
            [TokenRequest.Parameters.ActorToken] = actor[TokenResponse.Parameters.IdToken]!.GetValue<string>(),
            [TokenRequest.Parameters.ActorTokenType] = TokenExchangeTokenTypes.IdToken,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        Assert.Equal(expected, response.StatusCode);
        if (expected == HttpStatusCode.BadRequest)
        {
            var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.Equal(ErrorCodes.InvalidRequest, body?[ErrorResponse.Parameters.Error]?.GetValue<string>());
        }
    }

    [Fact]
    public async Task Cross_client_id_token_exchange_rejected_by_default()
    {
        // Client A obtains an id_token whose audience names client A. A different client B presents
        // that id_token as subject_token. The confused-deputy guard must reject the exchange even
        // though the id_token is a valid, AS-signed token: an id_token carries no client_id claim,
        // so its origin is recovered from the audience. Without that recovery any client could
        // exchange any user's id_token for an access token bound to itself.
        // Client A uses the session at logout, so its id_token names the session and only the origin is at issue
        var clientA = TestConstants.ConfidentialClientId;
        await using var host = Factory.WithSessionLogout();
        var client = CreateClientFor(host);
        var issued = await PerformParFlowAsync(
            clientA, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson, client: client);
        var idToken = issued[TokenResponse.Parameters.IdToken]!.GetValue<string>();

        // Premise of the finding: the id_token's aud is client A and it has no client_id claim.
        var idPayload = DecodeJwtPayload(idToken);
        Assert.Equal(clientA, idPayload["aud"]!.GetValue<string>());
        Assert.Null(idPayload[IanaClaimTypes.ClientId]);
        Assert.NotNull(idPayload[IanaClaimTypes.Sid]);

        var discovery = await FetchDiscoveryAsync(client);
        var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = TokenExchangeGrantType,
            [TokenRequest.Parameters.SubjectToken] = idToken,
            [TokenRequest.Parameters.SubjectTokenType] = TokenExchangeTokenTypes.IdToken,
            // Client B presents client A's id_token. Same shared secret across pre-seeded clients.
            [ClientRequest.Parameters.ClientId] = TestConstants.UnrestrictedClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.False(response.IsSuccessStatusCode,
            $"Expected cross-client exchange to be rejected, but got {(int)response.StatusCode}: {raw}");
        var error = JsonNode.Parse(raw)?.AsObject();
        Assert.Equal(ErrorCodes.InvalidRequest, error?[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// An exchange names a scope only within the subject token's scope, an empty one included: an access token
    /// carrying no scope is not exchanged for one carrying a scope, while a token carrying that scope is, and an ID
    /// token, which carries no scope claim at all, is not bounded by one.
    /// </summary>
    [Theory]
    [InlineData(null, false, HttpStatusCode.BadRequest)]
    [InlineData(Scopes.Profile, false, HttpStatusCode.OK)]
    [InlineData(Scopes.OpenId, true, HttpStatusCode.OK)]
    public async Task AnExchange_IsBoundByTheSubjectTokensScope(string? granted, bool idToken, HttpStatusCode expected)
    {
        // The client uses the session at logout, so its id_token names the session and can be exchanged at all
        await using var host = Factory.WithSessionLogout();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var (verifier, challenge) = GeneratePkcePair();
        var parameters = CodeFlowParameters(TestConstants.ConfidentialClientId, challenge);
        if (granted is null)
            parameters.Remove(AuthorizationRequest.Parameters.Scope);
        else
            parameters[AuthorizationRequest.Parameters.Scope] = granted;

        var code = await AuthorizeAndExtractCodeAsync(client, discovery, parameters);
        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        using var exchange = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = TokenExchangeGrantType,
            [TokenRequest.Parameters.SubjectToken] =
                tokens[idToken ? TokenResponse.Parameters.IdToken : TokenResponse.Parameters.AccessToken]!.GetValue<string>(),
            [TokenRequest.Parameters.SubjectTokenType] =
                idToken ? TokenExchangeTokenTypes.IdToken : TokenExchangeTokenTypes.AccessToken,
            [TokenRequest.Parameters.Scope] = Scopes.Profile,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        Assert.Equal(expected, exchange.StatusCode);
        if (expected == HttpStatusCode.BadRequest)
        {
            var body = JsonNode.Parse(await exchange.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
            Assert.Equal(ErrorCodes.InvalidScope, body?[ErrorResponse.Parameters.Error]?.GetValue<string>());
        }
    }

    /// <summary>
    /// Each token in a chain of exchanges expires no later than the token it was exchanged from, and its expires_in
    /// says so, while it tells of the sign-in the chain started from rather than of the moment of the exchange.
    /// </summary>
    /// <remarks>
    /// Each exchange waits a second first, so a token given a fresh lifetime would expire later than its subject
    /// token and a fresh authentication time would differ from the sign-in, both in the whole seconds a JWT states.
    /// An access token is taken both from a refresh token family and from outside one, since a token of a family was
    /// cut short to its subject token before any other was.
    /// </remarks>
    [Theory]
    [InlineData(TokenExchangeTokenTypes.AccessToken, true)]
    [InlineData(TokenExchangeTokenTypes.AccessToken, false)]
    [InlineData(TokenExchangeTokenTypes.IdToken, false)]
    [InlineData(TokenExchangeTokenTypes.RefreshToken, true)]
    public async Task A_chain_of_exchanges_never_outlives_its_subject_token_and_keeps_its_sign_in(
        string subjectTokenType, bool offline)
    {
        await using var host = Factory.WithSessionLogout();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = offline
            ? await ObtainConfidentialOfflineTokensAsync(client, discovery)
            : await ObtainConfidentialOnlineTokensAsync(client, discovery);
        var signedInAt = DecodeJwtPayload(tokens[TokenResponse.Parameters.IdToken]!.GetValue<string>())[IanaClaimTypes.AuthTime]!
            .GetValue<long>();

        var token = tokens[ResponseMemberOf(subjectTokenType)]!.GetValue<string>();
        var tokenType = subjectTokenType;
        for (var exchange = 1; exchange <= 2; exchange++)
        {
            var subjectExpiresAt = DecodeJwtPayload(token)[JwtClaimTypes.ExpiresAt]!.GetValue<long>();
            await Task.Delay(TimeSpan.FromSeconds(1.1), TestContext.Current.CancellationToken);

            var response = await ExchangeAsConfidentialClientAsync(client, discovery, token, tokenType);
            token = response[TokenResponse.Parameters.AccessToken]!.GetValue<string>();
            tokenType = TokenExchangeTokenTypes.AccessToken;

            var payload = DecodeJwtPayload(token);
            var expiresAt = payload[JwtClaimTypes.ExpiresAt]!.GetValue<long>();
            Assert.True(
                expiresAt <= subjectExpiresAt,
                $"exchange {exchange}: the token expires at {expiresAt}, after its subject token at {subjectExpiresAt}");
            Assert.Equal(
                expiresAt - payload[JwtClaimTypes.IssuedAt]!.GetValue<long>(),
                response[TokenResponse.Parameters.ExpiresIn]!.GetValue<long>());
            Assert.Equal(signedInAt, payload[IanaClaimTypes.AuthTime]!.GetValue<long>());
        }
    }

    /// <summary>
    /// The token response of an authorization code grant to the confidential client without offline access, so its
    /// access token belongs to no refresh token family.
    /// </summary>
    private static async Task<JsonObject> ObtainConfidentialOnlineTokensAsync(HttpClient client, DiscoveryDocument discovery)
    {
        var (verifier, challenge) = GeneratePkcePair();
        var code = await AuthorizeAndExtractCodeAsync(
            client, discovery, CodeFlowParameters(TestConstants.ConfidentialClientId, challenge));

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.AuthorizationCode,
            [TokenRequest.Parameters.Code] = code,
            [TokenRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [TokenRequest.Parameters.CodeVerifier] = verifier,
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });
        Assert.Null(DecodeJwtPayload(tokens[TokenResponse.Parameters.AccessToken]!.GetValue<string>())[OidcClaimTypes.GrantId]);
        return tokens;
    }

    private async Task<JsonObject> PerformTokenExchangeAsync(Dictionary<string, string> form)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        return await ExchangeCodeForTokensAsync(client, discovery, form);
    }

    private static HttpClient CreateClientFor(WebApplicationFactory<Program> host)
        => host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });
}
