// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// A client credentials request naming no scope is served with the client's default scope, or refused with
/// <c>invalid_scope</c> for a client required to name one: the two answers RFC 6749 section 3.3 allows a server.
/// </summary>
public class ClientDefaultScopeTests(TestFactory factory) : TestBase(factory)
{
    [Fact]
    public async Task ARequestNamingNoScope_IsIssuedATokenWithTheClientsDefault()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, Form(TestConstants.DefaultScopeClientId));

        var payload = DecodeJwtPayload(tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        Assert.Equal(Scopes.Profile, payload[IanaClaimTypes.Scope]?.GetValue<string>());
    }

    [Fact]
    public async Task ARequestNamingNoScope_OfAClientRequiredToNameOne_IsRefused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await FormPostHelpers.PostFormAsync(
            client, discovery.TokenEndpoint, Form(TestConstants.ScopeRequiredClientId));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidScope, body[ResponseParameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// A default made of a scope a resource declares serves a request naming that resource and no scope, as the same
    /// request naming the scope is served: the token carries the scope.
    /// </summary>
    [Fact]
    public async Task ARequestNamingAResourceAndNoScope_IsIssuedATokenWithTheResourcesDefaultScope()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var form = Form(TestConstants.DefaultResourceScopeClientId);
        form[TokenRequest.Parameters.Resource] = TestConstants.ApiResource;

        var tokens = await ExchangeCodeForTokensAsync(client, discovery, form);

        var payload = DecodeJwtPayload(tokens[UserInfoRequest.Parameters.AccessToken]!.GetValue<string>());
        Assert.Equal(TestConstants.ApiScope, payload[IanaClaimTypes.Scope]?.GetValue<string>());
    }

    /// <summary>
    /// The device authorization endpoint serves the same request, a resource and no scope, with the client's default,
    /// which the device code's stored request then carries.
    /// </summary>
    [Fact]
    public async Task ADeviceRequestNamingAResourceAndNoScope_IsServedWithTheResourcesDefaultScope()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);

        using var response = await FormPostHelpers.PostFormAsync(
            client,
            discovery.DeviceAuthorizationEndpoint!,
            new Dictionary<string, string>
            {
                [DeviceAuthorizationRequest.Parameters.Resource] = TestConstants.ApiResource,
                [ClientRequest.Parameters.ClientId] = TestConstants.DefaultResourceScopeClientId,
                [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            });
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.True(response.IsSuccessStatusCode, $"device authorization failed: {(int)response.StatusCode} {body}");
        var deviceCode = JsonNode.Parse(body)![DeviceAuthorizationResponse.Parameters.DeviceCode]!.GetValue<string>();

        using var tenant = TestTenant.Enter(Factory.Services);
        var stored = await Factory.Services.GetRequiredService<IDeviceAuthorizationStorage>().TryGetByDeviceCodeAsync(
            Factory.Services.GetRequiredService<ITenantAccessor>().CurrentTenant(),
            deviceCode);

        Assert.Equal(TestConstants.ApiScope, Assert.Single(stored?.Scope ?? []));
    }

    /// <summary>
    /// The token endpoint authenticates the client before it reads the resources, since a request naming no scope is
    /// judged with the client's default: a request failing both is refused as from a client that cannot authenticate.
    /// </summary>
    [Fact]
    public async Task ARequestOfAClientFailingToAuthenticate_IsRefusedForThatBeforeItsResource()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var form = Form(TestConstants.DefaultResourceScopeClientId);
        form[ClientRequest.Parameters.ClientSecret] = "not-the-secret";
        form[TokenRequest.Parameters.Resource] = "https://unknown.example.com/";

        using var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, form);

        var body = JsonNode.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken))!;
        Assert.Equal(ErrorCodes.InvalidClient, body[ResponseParameters.Error]?.GetValue<string>());
    }

    private static Dictionary<string, string> Form(string clientId) => new()
    {
        [TokenRequest.Parameters.GrantType] = GrantTypes.ClientCredentials,
        [AuthorizationRequest.Parameters.ClientId] = clientId,
        [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
    };
}
