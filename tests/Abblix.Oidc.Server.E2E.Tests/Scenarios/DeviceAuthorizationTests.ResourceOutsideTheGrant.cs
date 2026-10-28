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
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.DeviceAuthorization.Interfaces;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using DeviceRequest = Abblix.Oidc.Server.Model.DeviceAuthorizationRequest;
using DeviceResponse = Abblix.Oidc.Server.Model.DeviceAuthorizationResponse;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class DeviceAuthorizationTests
{
    /// <summary>
    /// A device code approved for one resource refuses a poll naming another beside it, as the token endpoint refuses
    /// it for every grant authorized before the token request.
    /// </summary>
    [Fact]
    public async Task A_poll_naming_a_resource_outside_its_grant_is_refused()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var device = await RegisterDeviceClientAsync(client, discovery, "device-resource-outside-grant");

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
                    new AuthorizationContext(device.ClientId, [Scopes.OpenId], null, [new Uri(TestConstants.ApiResource)])));
            Assert.True(approved);
        }

        var response = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint,
        [
            new(TokenRequest.Parameters.GrantType, GrantTypes.DeviceAuthorization),
            new(TokenRequest.Parameters.DeviceCode, deviceCode),
            new(ClientRequest.Parameters.ClientId, device.ClientId),
            new(ClientRequest.Parameters.ClientSecret, device.ClientSecret),
            new(TokenRequest.Parameters.Resource, TestConstants.ApiResource),
            new(TokenRequest.Parameters.Resource, TestConstants.OtherApiResource),
        ]);

        var body = await ReadJsonAsync(response);
        await AssertRefusedAsync(response, ErrorCodes.InvalidTarget);
        Assert.Equal(ResourceRefusals.NotGranted, body[ResponseParameters.ErrorDescription]?.GetValue<string>());
    }
}
