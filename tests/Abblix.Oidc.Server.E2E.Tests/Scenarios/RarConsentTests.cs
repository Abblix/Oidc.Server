// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9396 §5 consent-side handling of Rich Authorization Requests, end-to-end:
/// narrowing, deny-all, drop-entry from a multi-set, cross-detail amount caps,
/// null-grant passthrough, and refresh-token preservation of authorization_details.
/// Core round-trip lives in <see cref="RichAuthorizationRequestsTests"/> and the
/// metadata surface in <see cref="RarMetadataTests"/>; the three share
/// <see cref="RarTestBase"/>.
/// </summary>
public class RarConsentTests(TestFactory factory) : RarTestBase(factory)
{
    [Fact]
    public async Task Consent_narrowing_authorization_details_propagates_to_access_token()
    {
        const string narrowedWireJson =
            """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"200.00"}}]""";

        var claim = await AssertConsentNarrowSurvivesToAccessTokenAsync(
            PaymentInitiationWireJson, narrowedWireJson);

        Assert.DoesNotContain("500.00", claim.ToJsonString());
    }

    [Fact]
    public async Task Consent_denying_all_authorization_details_fails_with_access_denied()
    {
        // Provider explicitly returns empty Granted.AuthorizationDetails -> deny-all signal.
        var client = CreateClient();
        using var _ = client.UseConsentOverride(new JsonArray());
        var discovery = await FetchDiscoveryAsync(client);
        var (_, challenge) = GeneratePkcePair();

        var parResponse = await PushAuthorizationRequestAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [AuthorizationRequest.Parameters.ResponseType] = "code",
            [AuthorizationRequest.Parameters.RedirectUri] = TestConstants.RedirectUri,
            [AuthorizationRequest.Parameters.Scope] = Scopes.OpenId,
            [AuthorizationRequest.Parameters.CodeChallenge] = challenge,
            [AuthorizationRequest.Parameters.CodeChallengeMethod] = CodeChallengeMethods.S256,
            [AuthorizationRequest.Parameters.AuthorizationDetails] = PaymentInitiationWireJson,
        });
        var requestUri = parResponse[AuthorizationRequest.Parameters.RequestUri]!.GetValue<string>();

        var error = await AuthorizeAndExtractErrorAsync(client, discovery, new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [AuthorizationRequest.Parameters.RequestUri] = requestUri,
        });

        Assert.Equal("access_denied", error);
    }

    [Fact]
    public async Task Consent_drop_entry_from_multi_set_token_carries_only_remaining_entries()
    {
        // RFC 9396 §5 partial-consent drop-entry, E2E. Client requested two entries,
        // consent provider returns Granted.AuthorizationDetails with one entry only.
        const string requestedWireJson =
            """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}},{"type":"payment_initiation","actions":["status"],"instructedAmount":{"currency":"EUR","amount":"10.00"}}]""";
        const string survivingWireJson =
            """[{"type":"payment_initiation","actions":["status"],"instructedAmount":{"currency":"EUR","amount":"10.00"}}]""";

        var claim = await AssertConsentNarrowSurvivesToAccessTokenAsync(
            requestedWireJson, survivingWireJson);

        Assert.Single(claim);
        Assert.DoesNotContain("\"amount\":\"500.00\"", claim.ToJsonString());
    }

    [Fact]
    public async Task Consent_cross_detail_total_amount_cap_propagates_to_access_token()
    {
        // RFC 9396 §5 cross-detail policy, E2E. Three entries of 500.00 each; consent
        // provider zeroes the last to stay under a total-amount cap of 1000.00.
        const string requestedWireJson =
            """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}},{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}},{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";
        const string cappedWireJson =
            """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}},{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}},{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"0.00"}}]""";

        var claim = await AssertConsentNarrowSurvivesToAccessTokenAsync(
            requestedWireJson, cappedWireJson);

        Assert.Equal(3, claim.Count);
        Assert.Equal("0.00", claim[2]!["instructedAmount"]!["amount"]!.GetValue<string>());
    }

    [Fact]
    public async Task Consent_passthrough_when_provider_grants_null_preserves_request_value()
    {
        // No Override -> provider leaves Granted.AuthorizationDetails as null -> processor
        // falls back to the post-validator request value (PR #135 baseline behaviour).
        // Explicit anchor for the contract; functionally same path as the byte-exact tests
        // above, but stated as a #142 acceptance criterion in its own right.
        var tokenResponse = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);

        var payload = DecodeJwtPayload(tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        var claim = (payload[AuthorizationRequest.Parameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(PaymentInitiationWireJson, claim.ToJsonString());
    }

    [Fact]
    public async Task Refresh_token_grant_preserves_authorization_details_byte_exact()
    {
        var initial = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson,
            scope: Scopes.OpenId + " " + Scopes.OfflineAccess);
        var refreshToken = initial[GrantTypes.RefreshToken]?.GetValue<string>()
            ?? throw new InvalidOperationException("Initial token response missing refresh_token");

        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var refreshed = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.RefreshToken,
            [GrantTypes.RefreshToken] = refreshToken,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var payload = DecodeJwtPayload(refreshed[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        var claim = (payload[AuthorizationRequest.Parameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(PaymentInitiationWireJson, claim.ToJsonString());
    }

    /// <summary>
    /// Drives PAR / authorize / token with a consent-side override and asserts the issued
    /// access token's <c>authorization_details</c> claim equals the override byte-exact.
    /// Returns the claim so callers can layer additional assertions.
    /// </summary>
    private async Task<JsonArray> AssertConsentNarrowSurvivesToAccessTokenAsync(
        string requestedWireJson,
        string grantedWireJson)
    {
        var client = CreateClient();
        using var _ = client.UseConsentOverride((JsonArray)JsonNode.Parse(grantedWireJson)!);

        var tokenResponse = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, requestedWireJson, client: client);

        var payload = DecodeJwtPayload(tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        var claim = (payload[AuthorizationRequest.Parameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(grantedWireJson, claim.ToJsonString());
        return claim;
    }
}
