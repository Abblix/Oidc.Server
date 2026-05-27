// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
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

    private const string PaymentInitiationWireJson =
        """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";

    [Fact]
    public async Task Impersonation_preserves_subject_and_forwards_authorization_details()
    {
        // 1. Mint an access token via the standard auth-code flow.
        var initial = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);
        var subjectToken = initial["access_token"]!.GetValue<string>();
        var originalSubject = DecodeJwtPayload(subjectToken)["sub"]!.GetValue<string>();

        // 2. Exchange it via grant_type=token-exchange.
        var exchanged = await PerformTokenExchangeAsync(new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["client_id"] = TestConstants.ConfidentialClientId,
            ["client_secret"] = TestConstants.ConfidentialClientSecret,
        });

        // 3. Issued access token: same sub, AD forwarded byte-exact, no act claim.
        var newPayload = DecodeJwtPayload(exchanged["access_token"]!.GetValue<string>());
        Assert.Equal(originalSubject, newPayload["sub"]!.GetValue<string>());
        var ad = newPayload[WireParameters.AuthorizationDetails] as JsonArray;
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
        var subjectToken = subject["access_token"]!.GetValue<string>();
        var subjectSub = DecodeJwtPayload(subjectToken)["sub"]!.GetValue<string>();

        // 2. Mint the actor_token. Same client + flow stands in for a distinct service identity
        // -- the test exercises the act-chain wiring, not real cross-actor identity (TestHost has
        // a single auto-authenticated user).
        var actor = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);
        var actorToken = actor["access_token"]!.GetValue<string>();
        var actorSub = DecodeJwtPayload(actorToken)["sub"]!.GetValue<string>();

        // 3. Exchange with both subject_token and actor_token.
        var exchanged = await PerformTokenExchangeAsync(new Dictionary<string, string>
        {
            ["grant_type"] = TokenExchangeGrantType,
            ["subject_token"] = subjectToken,
            ["subject_token_type"] = AccessTokenType,
            ["actor_token"] = actorToken,
            ["actor_token_type"] = AccessTokenType,
            ["client_id"] = TestConstants.ConfidentialClientId,
            ["client_secret"] = TestConstants.ConfidentialClientSecret,
        });

        // 4. Issued token: sub = subject, act = { sub: actor }.
        var newPayload = DecodeJwtPayload(exchanged["access_token"]!.GetValue<string>());
        Assert.Equal(subjectSub, newPayload["sub"]!.GetValue<string>());
        var act = newPayload["act"] as JsonObject;
        Assert.NotNull(act);
        Assert.Equal(actorSub, act!["sub"]!.GetValue<string>());
    }

    private async Task<JsonObject> PerformTokenExchangeAsync(Dictionary<string, string> form)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        return await ExchangeCodeForTokensAsync(client, discovery, form);
    }
}
