// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using DeviceRequest = Abblix.Oidc.Server.Model.DeviceAuthorizationRequest;
using DeviceResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class DeviceAuthorizationTests
{
    /// <summary>
    /// A device code approved for a tenant scope and a scope only its resource declares is issued both whatever scope
    /// the poll names, one nobody declares included, since the poll defines no scope (RFC 8628 section 3.4) and the
    /// server ignores a parameter it does not recognize (RFC 6749 section 3.2) rather than refuse the code it spends.
    /// </summary>
    [Theory]
    [MemberData(nameof(ResourceScopeNarrowingTests.IgnoredRows), MemberType = typeof(ResourceScopeNarrowingTests))]
    public async Task A_poll_naming_a_scope_is_issued_its_grant(string named, bool namesResource)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var device = await RegisterDeviceClientAsync(client, discovery, "device-resource-scope");
        var requested = ResourceScopeNarrowingTests.Requested(named, Scopes.OpenId);

        var started = await ReadJsonAsync(await FormPostHelpers.PostFormAsync(
            client,
            discovery.DeviceAuthorizationEndpoint!,
            new Dictionary<string, string>
            {
                [DeviceRequest.Parameters.Scope] = $"{Scopes.OpenId} {TestConstants.ApiScope}",
                [DeviceRequest.Parameters.Resource] = TestConstants.ApiResource,
                [ClientRequest.Parameters.ClientId] = device.ClientId,
                [ClientRequest.Parameters.ClientSecret] = device.ClientSecret,
            }));
        var deviceCode = started[DeviceResponse.Parameters.DeviceCode]!.GetValue<string>();
        var userCode = started[DeviceResponse.Parameters.UserCode]!.GetValue<string>();

        using (TestTenant.Enter(Factory.Services))
        {
            using var scope = Factory.Services.CreateScope();
            var approved = await scope.ServiceProvider.GetRequiredService<IUserCodeVerificationService>().ApproveAsync(
                TestTenant.Of(Factory.Services),
                userCode,
                new AuthorizedGrant(
                    new AuthSession(
                        "e2e-subject",
                        Guid.NewGuid().ToString("N"),
                        scope.ServiceProvider.GetRequiredService<TimeProvider>().GetUtcNow(),
                        "e2e-test"),
                    new AuthorizationContext(
                        device.ClientId,
                        [Scopes.OpenId, TestConstants.ApiScope],
                        null,
                        [new Uri(TestConstants.ApiResource)])));
            Assert.True(approved);
        }

        using var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint,
        [
            new(TokenRequest.Parameters.GrantType, GrantTypes.DeviceAuthorization),
            new(TokenRequest.Parameters.DeviceCode, deviceCode),
            new(TokenRequest.Parameters.Scope, string.Join(' ', requested)),
            new(ClientRequest.Parameters.ClientId, device.ClientId),
            new(ClientRequest.Parameters.ClientSecret, device.ClientSecret),
            .. namesResource
                ? [new KeyValuePair<string, string>(TokenRequest.Parameters.Resource, TestConstants.ApiResource)]
                : Array.Empty<KeyValuePair<string, string>>(),
        ]);

        var body = await ReadJsonAsync(response);
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"expected 200, got {(int)response.StatusCode}: {body}");
        AssertIssuedScope([Scopes.OpenId, TestConstants.ApiScope], body);
    }

    /// <summary>
    /// A poll naming a scope is not refused for a token its grant leaves with none, as a poll naming none is not: the
    /// scope it names is ignored, so it cannot refuse the device code the poll spends.
    /// </summary>
    [Fact]
    public async Task A_poll_naming_a_scope_for_a_token_left_with_none_is_answered()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var device = await RegisterDeviceClientAsync(client, discovery, "device-scope-left-none");

        var started = await ReadJsonAsync(await FormPostHelpers.PostFormAsync(
            client,
            discovery.DeviceAuthorizationEndpoint!,
            new Dictionary<string, string>
            {
                [DeviceRequest.Parameters.Scope] = Scopes.OpenId,
                [DeviceRequest.Parameters.Resource] = TestConstants.ApiResource,
                [ClientRequest.Parameters.ClientId] = device.ClientId,
                [ClientRequest.Parameters.ClientSecret] = device.ClientSecret,
            }));
        var deviceCode = started[DeviceResponse.Parameters.DeviceCode]!.GetValue<string>();
        var userCode = started[DeviceResponse.Parameters.UserCode]!.GetValue<string>();

        // A scope only a resource the token is not addressed to declares, served as a default the client never named,
        // leaves the token with no scope
        using (TestTenant.Enter(Factory.Services))
        {
            using var scope = Factory.Services.CreateScope();
            var approved = await scope.ServiceProvider.GetRequiredService<IUserCodeVerificationService>().ApproveAsync(
                TestTenant.Of(Factory.Services),
                userCode,
                new AuthorizedGrant(
                    new AuthSession(
                        "e2e-subject",
                        Guid.NewGuid().ToString("N"),
                        scope.ServiceProvider.GetRequiredService<TimeProvider>().GetUtcNow(),
                        "e2e-test"),
                    new AuthorizationContext(
                        device.ClientId,
                        [TestConstants.OtherApiScope],
                        null,
                        [new Uri(TestConstants.ApiResource)])
                    {
                        ClientNamedNoScope = true,
                    }));
            Assert.True(approved);
        }

        using var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint,
        [
            new(TokenRequest.Parameters.GrantType, GrantTypes.DeviceAuthorization),
            new(TokenRequest.Parameters.DeviceCode, deviceCode),
            new(TokenRequest.Parameters.Scope, Scopes.OpenId),
            new(ClientRequest.Parameters.ClientId, device.ClientId),
            new(ClientRequest.Parameters.ClientSecret, device.ClientSecret),
        ]);

        var body = await ReadJsonAsync(response);
        Assert.True(response.StatusCode == HttpStatusCode.OK, $"expected 200, got {(int)response.StatusCode}: {body}");
    }
}
