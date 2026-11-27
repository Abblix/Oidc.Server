// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
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
        var (device, deviceCode) = await ApprovedDeviceCodeAsync(
            client,
            discovery,
            "device-resource-scope",
            $"{Scopes.OpenId} {TestConstants.ApiScope}",
            [Scopes.OpenId, TestConstants.ApiScope]);

        using var response = await PollAsync(
            client,
            discovery,
            device,
            deviceCode,
            ScopeNaming(ResourceScopeNarrowingTests.Requested(named, Scopes.OpenId), namesResource));

        AssertIssuedScope([Scopes.OpenId, TestConstants.ApiScope], await AssertAnsweredAsync(response));
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

        // Only an offline_access a client of this grant alone may not receive, so the client names no scope, and a
        // scope only a resource the token is not addressed to declares leaves the token with none
        var (device, deviceCode) = await ApprovedDeviceCodeAsync(
            client,
            discovery,
            "device-scope-left-none",
            Scopes.OfflineAccess,
            [TestConstants.OtherApiScope]);

        using var response = await PollAsync(
            client,
            discovery,
            device,
            deviceCode,
            [new(TokenRequest.Parameters.Scope, Scopes.OpenId)]);

        await AssertAnsweredAsync(response);
    }

    /// <summary>
    /// A device code a registered client started for <paramref name="startScope"/> and the test resource, approved for
    /// <paramref name="grantedScope"/> on that resource.
    /// </summary>
    private async Task<(DeviceClient Device, string DeviceCode)> ApprovedDeviceCodeAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        string clientName,
        string startScope,
        string[] grantedScope)
    {
        var device = await RegisterDeviceClientAsync(client, discovery, clientName);
        var started = await ReadJsonAsync(await FormPostHelpers.PostFormAsync(
            client,
            discovery.DeviceAuthorizationEndpoint!,
            new Dictionary<string, string>
            {
                [DeviceRequest.Parameters.Scope] = startScope,
                [DeviceRequest.Parameters.Resource] = TestConstants.ApiResource,
                [ClientRequest.Parameters.ClientId] = device.ClientId,
                [ClientRequest.Parameters.ClientSecret] = device.ClientSecret,
            }));

        using (TestTenant.Enter(Factory.Services))
        {
            using var scope = Factory.Services.CreateScope();
            var approved = await scope.ServiceProvider.GetRequiredService<IUserCodeVerificationService>().ApproveAsync(
                TestTenant.Of(Factory.Services),
                started[DeviceResponse.Parameters.UserCode]!.GetValue<string>(),
                new AuthorizedGrant(
                    new AuthSession(
                        "e2e-subject",
                        Guid.NewGuid().ToString("N"),
                        scope.ServiceProvider.GetRequiredService<TimeProvider>().GetUtcNow(),
                        "e2e-test"),
                    new AuthorizationContext(
                        device.ClientId,
                        grantedScope,
                        null,
                        [new Uri(TestConstants.ApiResource)])));
            Assert.True(approved);
        }

        return (device, started[DeviceResponse.Parameters.DeviceCode]!.GetValue<string>());
    }

    /// <summary>A poll for <paramref name="deviceCode"/> as <paramref name="device"/>, carrying
    /// <paramref name="parameters"/> too.</summary>
    private static Task<HttpResponseMessage> PollAsync(
        HttpClient client,
        DiscoveryDocument discovery,
        DeviceClient device,
        string deviceCode,
        IEnumerable<KeyValuePair<string, string>> parameters)
        => FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint,
        [
            new(TokenRequest.Parameters.GrantType, GrantTypes.DeviceAuthorization),
            new(TokenRequest.Parameters.DeviceCode, deviceCode),
            new(ClientRequest.Parameters.ClientId, device.ClientId),
            new(ClientRequest.Parameters.ClientSecret, device.ClientSecret),
            .. parameters,
        ]);
}
