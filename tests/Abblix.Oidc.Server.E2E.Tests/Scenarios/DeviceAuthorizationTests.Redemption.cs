// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class DeviceAuthorizationTests
{
    /// <summary>
    /// A device code is spent only once tokens are issued for it: a poll refused for naming a resource outside its
    /// grant leaves it for the poll naming the granted one, and a device code tokens were issued for is refused the
    /// next time.
    /// </summary>
    [Fact]
    public async Task A_poll_refused_a_resource_outside_its_grant_leaves_the_device_code_for_the_corrected_one()
    {
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (device, deviceCode) = await ApprovedDeviceCodeAsync(
            client, discovery, "device-refused-then-redeemed", Scopes.OpenId, [Scopes.OpenId]);

        using var refused = await PollAsync(
            client, discovery, device, deviceCode,
            [new(TokenRequest.Parameters.Resource, TestConstants.OtherApiResource)]);
        await AssertRefusedAsync(refused, ErrorCodes.InvalidTarget);

        using var granted = await PollAsync(
            client, discovery, device, deviceCode,
            [new(TokenRequest.Parameters.Resource, TestConstants.ApiResource)]);
        await AssertAnsweredAsync(granted);

        using var reused = await PollAsync(client, discovery, device, deviceCode, []);
        Assert.Equal(HttpStatusCode.BadRequest, reused.StatusCode);
    }

    /// <summary>
    /// Polls redeeming one approved device code at once, each of which would be issued tokens alone, are issued
    /// exactly one set.
    /// </summary>
    [Fact]
    public async Task A_device_code_redeemed_by_concurrent_polls_is_redeemed_once()
    {
        const int polls = 8;
        var client = CreateClient();
        var discovery = await FetchDiscoveryAsync(client);
        var (device, deviceCode) = await ApprovedDeviceCodeAsync(
            client, discovery, "device-concurrent-polls", Scopes.OpenId, [Scopes.OpenId]);

        var responses = await Task.WhenAll(Enumerable.Range(0, polls)
            .Select(_ => PollAsync(client, discovery, device, deviceCode, [])));
        try
        {
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
            Assert.All(
                responses.Where(response => response.StatusCode != HttpStatusCode.OK),
                response => Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode));
        }
        finally
        {
            foreach (var response in responses)
                response.Dispose();
        }
    }
}
