// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Common.Constants;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9396 Rich Authorization Requests end-to-end against the test
/// OIDC provider. Each test drives the full HTTP flow as a real RP —
/// no internal-API shortcuts — and asserts on the wire shape of what
/// crosses the boundary.
/// </summary>
public class RichAuthorizationRequestsTests(TestFactory factory) : TestBase(factory)
{
    private const string PaymentInitiationWireJson =
        """[{"type":"payment_initiation","actions":["initiate"],"instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";

    private const string MultiEntryWireJson =
        """[{"type":"payment_initiation","actions":["initiate","status"],"instructedAmount":{"currency":"EUR","amount":"500.00"}},{"type":"payment_initiation","actions":["status"],"instructedAmount":{"currency":"EUR","amount":"10.00"}}]""";

    private const string AccountInformationWireJson =
        """[{"type":"account_information","identifier":"acct-001"}]""";

    private const string PaymentInitiationMissingActionsJson =
        """[{"type":"payment_initiation","instructedAmount":{"currency":"EUR","amount":"500.00"}}]""";

    [Fact]
    public async Task Par_then_authorize_then_token_round_trips_authorization_details_byte_exact()
    {
        var tokenResponse = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);

        // RFC 9396 §7: authorization_details echoed byte-exact in the token response
        var echoed = (tokenResponse[AuthorizationRequest.Parameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(PaymentInitiationWireJson, echoed.ToJsonString());

        // Access token carries the claim byte-exact
        var payload = DecodeJwtPayload(tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        var claim = (payload[AuthorizationRequest.Parameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(PaymentInitiationWireJson, claim.ToJsonString());
    }

    [Fact]
    public async Task Multi_entry_authorization_details_preserves_member_order()
    {
        var tokenResponse = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, MultiEntryWireJson);

        var echoed = (tokenResponse[AuthorizationRequest.Parameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(MultiEntryWireJson, echoed.ToJsonString());
        Assert.Equal(2, echoed.Count);
    }

    [Fact]
    public async Task Id_token_carries_authorization_details_when_client_toggle_on()
    {
        var tokenResponse = await PerformParFlowAsync(
            TestConstants.IdTokenRarClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);

        var idTokenPayload = DecodeJwtPayload(tokenResponse[BackChannelTokenPushRequest.Parameters.IdToken]!.GetValue<string>());
        var claim = (idTokenPayload[AuthorizationRequest.Parameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(PaymentInitiationWireJson, claim.ToJsonString());
    }

    [Fact]
    public async Task Id_token_omits_authorization_details_when_client_toggle_off()
    {
        var tokenResponse = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);

        var idTokenPayload = DecodeJwtPayload(tokenResponse[BackChannelTokenPushRequest.Parameters.IdToken]!.GetValue<string>());
        Assert.Null(idTokenPayload[AuthorizationRequest.Parameters.AuthorizationDetails]);
    }

    [Fact]
    public Task Empty_allowlist_client_is_rejected_with_invalid_authorization_details() =>
        AssertParRejectedWithInvalidAuthorizationDetailsAsync(
            TestConstants.EmptyAllowlistClientId, PaymentInitiationWireJson);

    [Fact]
    public Task Allowlisted_client_rejects_authorization_detail_type_not_in_allowlist() =>
        AssertParRejectedWithInvalidAuthorizationDetailsAsync(
            TestConstants.ConfidentialClientId, AccountInformationWireJson);

    [Fact]
    public Task Unrestricted_client_still_rejects_type_without_a_registered_validator() =>
        AssertParRejectedWithInvalidAuthorizationDetailsAsync(
            TestConstants.UnrestrictedClientId, AccountInformationWireJson);

    [Fact]
    public Task Validator_rejects_payment_initiation_payload_missing_required_actions_member() =>
        AssertParRejectedWithInvalidAuthorizationDetailsAsync(
            TestConstants.ConfidentialClientId, PaymentInitiationMissingActionsJson);

    [Fact]
    public async Task Discovery_exposes_token_exchange_grant_type()
    {
        // RFC 8693 §5: AS that supports Token Exchange MUST advertise it in grant_types_supported.
        // Automatic exposure via AddTokenExchangeGrant() -> AddAuthorizationGrant<TokenExchangeGrantHandler>,
        // CompositeAuthorizationGrantHandler aggregates GrantTypesSupported across all registered
        // handlers and the discovery pipeline reads from it.
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        Assert.NotNull(discovery.GrantTypesSupported);
        Assert.Contains("urn:ietf:params:oauth:grant-type:token-exchange", discovery.GrantTypesSupported!);
    }

    [Fact]
    public async Task Discovery_exposes_authorization_details_types_supported()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        Assert.NotNull(discovery.AuthorizationDetailsTypesSupported);
        Assert.Contains(TestConstants.PaymentInitiationType, discovery.AuthorizationDetailsTypesSupported!);
    }

    [Fact]
    public async Task Dynamic_client_registration_round_trips_authorization_details_types_metadata()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var requested = new JsonObject
        {
            ["redirect_uris"] = new JsonArray { TestConstants.RedirectUri },
            ["grant_types"] = new JsonArray { GrantTypes.AuthorizationCode },
            ["response_types"] = new JsonArray { "code" },
            ["token_endpoint_auth_method"] = "client_secret_post",
            ["authorization_details_types"] = new JsonArray { TestConstants.PaymentInitiationType },
        };
        var registered = await RegisterClientAsync(client, discovery, requested);

        var echoed = registered["authorization_details_types"] as JsonArray;
        Assert.NotNull(echoed);
        Assert.Single(echoed);
        Assert.Equal(TestConstants.PaymentInitiationType, echoed[0]!.GetValue<string>());
    }

    [Fact]
    public async Task Embedded_test_license_rejects_any_issuer_other_than_TestConstants_Issuer()
    {
        // The embedded test license declares valid_issuers = [TestConstants.Issuer] only.
        // Loading it at TestHost startup registers a permissive license, but
        // LicenseChecker.CheckIssuer throws on any issuer that is not on that whitelist —
        // physically preventing the license from being lifted into a production host with
        // a different issuer URL. Touch a client first so the WebApplicationFactory bootstraps
        // the host (which is what triggers LicenseLoader.LoadAsync on the embedded JWT).
        var client = CreateClient();
        _ = await FetchDiscoveryAsync(client);

        Assert.Equal(TestConstants.Issuer, LicenseChecker.CheckIssuer(TestConstants.Issuer));

        var ex = Assert.Throws<InvalidOperationException>(
            () => LicenseChecker.CheckIssuer("https://attacker.example.com"));
        Assert.Contains("license", ex.Message, StringComparison.OrdinalIgnoreCase);
    }

    [Fact]
    public async Task Introspection_response_echoes_authorization_details_from_access_token(/* RFC 9396 §9.2 */)
    {
        var tokenResponse = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);
        var accessToken = tokenResponse[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>();

        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.IntrospectionEndpoint);

        using var introspectRequest = new HttpRequestMessage(HttpMethod.Post, discovery.IntrospectionEndpoint);
        introspectRequest.Content = new FormUrlEncodedContent(new Dictionary<string, string>
        {
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            ["token"] = accessToken,
            ["token_type_hint"] = UserInfoRequest.Parameters.AccessToken,
        });
        var response = await client.SendAsync(introspectRequest, TestContext.Current.CancellationToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"introspect failed: {(int)response.StatusCode} {raw}");

        var body = JsonNode.Parse(raw)?.AsObject();
        Assert.NotNull(body);
        Assert.Equal("true", body["active"]?.GetValue<string>());

        var echoed = body[AuthorizationRequest.Parameters.AuthorizationDetails] as JsonArray;
        Assert.NotNull(echoed);
        Assert.Equal(PaymentInitiationWireJson, echoed.ToJsonString());
    }

    // ───────────────────────────────────────────────────────────────────────
    // RFC 9396 consent capture (#142). The configurable AutoConsentsProvider
    // models the three canonical Granted.AuthorizationDetails values:
    //   - non-empty array  -> user consented to a (possibly narrowed) set
    //   - empty JsonArray  -> user denied every entry
    //   - null (no override) -> legacy provider, pipeline passes the request
    //                           through unchanged (PR #135 baseline)
    // ───────────────────────────────────────────────────────────────────────

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
}
