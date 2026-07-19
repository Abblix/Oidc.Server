// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Common.Constants;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 8693 Token Exchange end-to-end against the test OIDC provider. Each test obtains a real
/// access token via the auth-code path first, then exercises the token-exchange grant at the
/// /token endpoint and asserts on the wire shape of the issued JWT.
/// </summary>
public class TokenExchangeTests(TestFactory factory) : TestBase(factory)
{
    private const string TokenExchangeGrantType = "urn:ietf:params:oauth:grant-type:token-exchange";
    private const string AccessTokenType = "urn:ietf:params:oauth:token-type:access_token";
    private const string IdTokenType = "urn:ietf:params:oauth:token-type:id_token";

    private const string PaymentInitiationWireJson =
        """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";

    [Fact]
    public async Task Impersonation_preserves_subject_and_forwards_authorization_details()
    {
        // 1. Mint an access token via the standard auth-code flow.
        var initial = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);
        var subjectToken = initial[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var originalSubject = DecodeJwtPayload(subjectToken)["sub"]!.GetValue<string>();

        // 2. Exchange it via grant_type=token-exchange.
        var exchanged = await PerformTokenExchangeAsync(new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = TokenExchangeGrantType,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        // 3. Issued access token: same sub, AD forwarded byte-exact, no act claim.
        var newPayload = DecodeJwtPayload(exchanged[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        Assert.Equal(originalSubject, newPayload["sub"]!.GetValue<string>());
        var ad = newPayload[AuthorizationRequest.Parameters.AuthorizationDetails] as JsonArray;
        Assert.NotNull(ad);
        Assert.Equal(PaymentInitiationWireJson, ad!.ToJsonString());
        Assert.Null(newPayload["act"]);
    }

    [Fact]
    public async Task Delegation_emits_act_claim_with_actor_subject()
    {
        // 1. Mint the subject_token (the principal acting through the actor).
        var subject = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);
        var subjectToken = subject[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var subjectSub = DecodeJwtPayload(subjectToken)["sub"]!.GetValue<string>();

        // 2. Mint the actor_token. Same client + flow stands in for a distinct service identity
        // -- the test exercises the act-chain wiring, not real cross-actor identity (TestHost has
        // a single auto-authenticated user).
        var actor = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);
        var actorToken = actor[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();
        var actorSub = DecodeJwtPayload(actorToken)["sub"]!.GetValue<string>();

        // 3. Exchange with both subject_token and actor_token.
        var exchanged = await PerformTokenExchangeAsync(new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = TokenExchangeGrantType,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["actor_token"] = actorToken,
            ["actor_token_type"] = AccessTokenType,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        // 4. Issued token: sub = subject, act = { sub: actor }.
        var newPayload = DecodeJwtPayload(exchanged[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        Assert.Equal(subjectSub, newPayload["sub"]!.GetValue<string>());
        var act = newPayload["act"] as JsonObject;
        Assert.NotNull(act);
        Assert.Equal(actorSub, act!["sub"]!.GetValue<string>());
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
            ["redirect_uris"] = new JsonArray { TestConstants.RedirectUri },
            ["grant_types"] = new JsonArray { GrantTypes.AuthorizationCode },
            ["response_types"] = new JsonArray { "code" },
            ["token_endpoint_auth_method"] = "client_secret_post",
            ["token_exchange_subject_token_types"] = new JsonArray
            {
                "urn:ietf:params:oauth:token-type:access_token",
                "urn:ietf:params:oauth:token-type:id_token",
            },
        };
        var registered = await RegisterClientAsync(client, discovery, requested);

        var echoed = registered["token_exchange_subject_token_types"] as JsonArray;
        Assert.NotNull(echoed);
        Assert.Equal(2, echoed!.Count);
        Assert.Equal("urn:ietf:params:oauth:token-type:access_token", echoed[0]!.GetValue<string>());
        Assert.Equal("urn:ietf:params:oauth:token-type:id_token", echoed[1]!.GetValue<string>());
    }

    [Fact]
    public async Task Cross_client_id_token_exchange_rejected_by_default()
    {
        // Client A obtains an id_token whose audience names client A. A different client B presents
        // that id_token as subject_token. The confused-deputy guard must reject the exchange even
        // though the id_token is a valid, AS-signed token: an id_token carries no client_id claim,
        // so its origin is recovered from the audience. Without that recovery any client could
        // exchange any user's id_token for an access token bound to itself.
        var clientA = TestConstants.ConfidentialClientId;
        var issued = await PerformParFlowAsync(
            clientA, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);
        var idToken = issued["id_token"]!.GetValue<string>();

        // Premise of the finding: the id_token's aud is client A and it has no client_id claim.
        var idPayload = DecodeJwtPayload(idToken);
        Assert.Equal(clientA, idPayload["aud"]!.GetValue<string>());
        Assert.Null(idPayload["client_id"]);

        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = TokenExchangeGrantType,
            ["subject_token"] = idToken,
            ["subject_token_type"] = IdTokenType,
            // Client B presents client A's id_token. Same shared secret across pre-seeded clients.
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.UnrestrictedClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.False(response.IsSuccessStatusCode,
            $"Expected cross-client exchange to be rejected, but got {(int)response.StatusCode}: {raw}");
        var error = JsonNode.Parse(raw)?.AsObject();
        Assert.Equal(ErrorCodes.InvalidRequest, error?["error"]?.GetValue<string>());
    }

    private async Task<JsonObject> PerformTokenExchangeAsync(Dictionary<string, string> form)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        return await ExchangeCodeForTokensAsync(client, discovery, form);
    }
}
