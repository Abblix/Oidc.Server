// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class DeviceAuthorizationTests
{
    /// <summary>
    /// A device code approved for one resource refuses a poll naming another, alone or beside it, as the token endpoint
    /// refuses it for every grant authorized before the token request.
    /// </summary>
    [Theory]
    [InlineData(false)]
    [InlineData(true)]
    public async Task A_poll_naming_a_resource_outside_its_grant_is_refused(bool alsoNamesTheGranted)
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (device, deviceCode) = await ApprovedDeviceCodeAsync(
            client,
            discovery,
            "device-resource-outside-grant",
            Scopes.OpenId,
            [Scopes.OpenId]);

        string[] named = alsoNamesTheGranted
            ? [TestConstants.ApiResource, TestConstants.OtherApiResource]
            : [TestConstants.OtherApiResource];
        var response = await PollAsync(
            client,
            discovery,
            device,
            deviceCode,
            named.Select(resource => new KeyValuePair<string, string>(TokenRequest.Parameters.Resource, resource)));

        var body = await ReadJsonAsync(response);
        await AssertRefusedAsync(response, ErrorCodes.InvalidTarget);
        Assert.Equal(ResourceRefusals.NotGranted, body[ErrorResponse.Parameters.ErrorDescription]?.GetValue<string>());
    }
}
