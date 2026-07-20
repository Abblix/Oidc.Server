// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Common.Constants;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// RFC 8707 Resource Indicators end-to-end against the test OIDC provider. The client_credentials
/// grant is the canonical resource-indicator scenario: it is a direct grant with no prior
/// authorization step, so the requested resource is itself the authorized audience and must land
/// in the issued access token's aud claim.
/// </summary>
public class ResourceIndicatorTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task ClientCredentials_with_registered_resource_sets_token_audience()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.Resource] = TestConstants.ApiResource,
        });

        var payload = DecodeJwtPayload(tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        var audiences = ExtractAudiences(payload);

        // The requested resource is the audience; the client id is NOT folded in alongside it.
        Assert.Contains(TestConstants.ApiResource, audiences);
        Assert.DoesNotContain(TestConstants.ClientCredentialsClientId, audiences);
    }

    [Fact]
    public async Task ClientCredentials_without_resource_falls_back_to_client_id_audience()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
        });

        var payload = DecodeJwtPayload(tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        var audiences = ExtractAudiences(payload);

        // No resource indicator: the OIDC convention falls back to the client id as the audience.
        Assert.Contains(TestConstants.ClientCredentialsClientId, audiences);
    }

    [Fact]
    public async Task ClientCredentials_with_unregistered_resource_is_rejected_as_invalid_target()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
            [AuthorizationRequest.Parameters.ClientId] = TestConstants.ClientCredentialsClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.Resource] = "https://unregistered.example.com/api",
        });

        var raw = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.False(response.IsSuccessStatusCode,
            $"Expected invalid_target rejection, but got {(int)response.StatusCode}: {raw}");
        var error = JsonNode.Parse(raw)?.AsObject();
        Assert.Equal(ErrorCodes.InvalidTarget, error?[ResponseParameters.Error]?.GetValue<string>());
    }

    // RFC 7519 §4.1.3: aud is serialized as a single string when there is one value, or an array
    // when there are several. Normalize both shapes to a flat list for assertion.
    private static string[] ExtractAudiences(JsonObject payload) =>
        payload[JwtClaimTypes.Audience] switch
        {
            JsonArray array => array.Select(node => node!.GetValue<string>()).ToArray(),
            JsonValue value => [value.GetValue<string>()],
            _ => [],
        };
}
