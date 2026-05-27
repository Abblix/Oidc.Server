// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Features.Licensing;
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
        var echoed = (tokenResponse[WireParameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(PaymentInitiationWireJson, echoed.ToJsonString());

        // Access token carries the claim byte-exact
        var payload = DecodeJwtPayload(tokenResponse["access_token"]!.GetValue<string>());
        var claim = (payload[WireParameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(PaymentInitiationWireJson, claim.ToJsonString());
    }

    [Fact]
    public async Task Multi_entry_authorization_details_preserves_member_order()
    {
        var tokenResponse = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, MultiEntryWireJson);

        var echoed = (tokenResponse[WireParameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(MultiEntryWireJson, echoed.ToJsonString());
        Assert.Equal(2, echoed.Count);
    }

    [Fact]
    public async Task Id_token_carries_authorization_details_when_client_toggle_on()
    {
        var tokenResponse = await PerformParFlowAsync(
            TestConstants.IdTokenRarClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);

        var idTokenPayload = DecodeJwtPayload(tokenResponse["id_token"]!.GetValue<string>());
        var claim = (idTokenPayload[WireParameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(PaymentInitiationWireJson, claim.ToJsonString());
    }

    [Fact]
    public async Task Id_token_omits_authorization_details_when_client_toggle_off()
    {
        var tokenResponse = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson);

        var idTokenPayload = DecodeJwtPayload(tokenResponse["id_token"]!.GetValue<string>());
        Assert.Null(idTokenPayload[WireParameters.AuthorizationDetails]);
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
            ["grant_types"] = new JsonArray { "authorization_code" },
            ["response_types"] = new JsonArray { "code" },
            ["token_endpoint_auth_method"] = "client_secret_post",
            ["authorization_details_types"] = new JsonArray { TestConstants.PaymentInitiationType },
        };
        var registered = await RegisterClientAsync(client, discovery, requested);

        var echoed = registered["authorization_details_types"] as JsonArray;
        Assert.NotNull(echoed);
        Assert.Single(echoed!);
        Assert.Equal(TestConstants.PaymentInitiationType, echoed![0]!.GetValue<string>());
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
        var accessToken = tokenResponse["access_token"]!.GetValue<string>();

        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        Assert.NotNull(discovery.IntrospectionEndpoint);

        using var introspectRequest = new HttpRequestMessage(HttpMethod.Post, discovery.IntrospectionEndpoint)
        {
            Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [WireParameters.ClientId] = TestConstants.ConfidentialClientId,
                [WireParameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
                ["token"] = accessToken,
                ["token_type_hint"] = "access_token",
            }),
        };
        var response = await client.SendAsync(introspectRequest);
        var raw = await response.Content.ReadAsStringAsync();
        Assert.True(response.IsSuccessStatusCode, $"introspect failed: {(int)response.StatusCode} {raw}");

        var body = JsonNode.Parse(raw)?.AsObject();
        Assert.NotNull(body);
        Assert.Equal("true", body!["active"]?.GetValue<string>());
        var echoed = body[WireParameters.AuthorizationDetails] as JsonArray;
        Assert.NotNull(echoed);
        Assert.Equal(PaymentInitiationWireJson, echoed!.ToJsonString());
    }

    [Fact]
    public async Task Refresh_token_grant_preserves_authorization_details_byte_exact()
    {
        var initial = await PerformParFlowAsync(
            TestConstants.ConfidentialClientId, TestConstants.ConfidentialClientSecret,
            TestConstants.RedirectUri, PaymentInitiationWireJson,
            scope: "openid offline_access");
        var refreshToken = initial["refresh_token"]?.GetValue<string>()
            ?? throw new InvalidOperationException("Initial token response missing refresh_token");

        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var refreshed = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            ["grant_type"] = "refresh_token",
            ["refresh_token"] = refreshToken,
            ["client_id"] = TestConstants.ConfidentialClientId,
            ["client_secret"] = TestConstants.ConfidentialClientSecret,
        });

        var payload = DecodeJwtPayload(refreshed["access_token"]!.GetValue<string>());
        var claim = (payload[WireParameters.AuthorizationDetails] as JsonArray)!;
        Assert.Equal(PaymentInitiationWireJson, claim.ToJsonString());
    }
}
