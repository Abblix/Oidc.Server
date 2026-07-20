// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Introspection.Interfaces;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.Model;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 9396 / RFC 8693 server-metadata surface for Rich Authorization Requests:
/// discovery advertisement (grant types, authorization_details_types_supported),
/// DCR round-trip of authorization_details_types, the embedded-license issuer
/// whitelist, and introspection echo of authorization_details (§9.2). Core round-trip
/// lives in <see cref="RichAuthorizationRequestsTests"/> and consent in
/// <see cref="RarConsentTests"/>; the three share <see cref="RarTestBase"/>.
/// </summary>
public class RarMetadataTests(TestFactory factory) : RarTestBase(factory)
{
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
            [RegistrationMembers.RedirectUris] = new JsonArray { TestConstants.RedirectUri },
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
            [IntrospectionRequest.Parameters.Token] = accessToken,
            [IntrospectionRequest.Parameters.TokenTypeHint] = UserInfoRequest.Parameters.AccessToken,
        });
        var response = await client.SendAsync(introspectRequest, TestContext.Current.CancellationToken);
        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"introspect failed: {(int)response.StatusCode} {raw}");

        var body = JsonNode.Parse(raw)?.AsObject();
        Assert.NotNull(body);
        Assert.True(body[IntrospectionSuccess.Parameters.Active]!.GetValue<bool>());

        var echoed = body[AuthorizationRequest.Parameters.AuthorizationDetails] as JsonArray;
        Assert.NotNull(echoed);
        Assert.Equal(PaymentInitiationWireJson, echoed.ToJsonString());
    }
}
