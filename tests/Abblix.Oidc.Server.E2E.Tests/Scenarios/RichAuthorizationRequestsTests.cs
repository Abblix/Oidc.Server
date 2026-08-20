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
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9396 Rich Authorization Requests end-to-end against the test OIDC provider:
/// authorization_details round-trip (byte-exact echo, member order, id_token toggle)
/// and validation/rejection (allowlist enforcement, missing required members). Each
/// test drives the full HTTP flow as a real RP - no internal-API shortcuts - and
/// asserts on the wire shape of what crosses the boundary. Discovery/DCR/introspection
/// metadata lives in <see cref="RarMetadataTests"/> and consent narrowing in
/// <see cref="RarConsentTests"/>; the three share <see cref="RarTestBase"/>.
/// </summary>
public class RichAuthorizationRequestsTests(TestFactory factory) : RarTestBase(factory)
{
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
}
