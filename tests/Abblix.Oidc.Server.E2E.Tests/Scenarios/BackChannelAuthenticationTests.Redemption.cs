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

public partial class BackChannelAuthenticationTests
{
    /// <summary>
    /// A backchannel authentication request is spent only once tokens are issued for it: a token request refused for
    /// naming a resource outside its grant leaves it for the one naming the granted resource, and a request tokens were
    /// issued for is refused the next time.
    /// </summary>
    [Fact]
    public async Task A_redemption_refused_a_resource_outside_its_grant_leaves_the_request_for_the_corrected_one()
    {
        await using var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var (ciba, authRequestId) = await AuthenticatedRequestAsync(
            host, client, discovery, Scopes.OpenId, grantedScope: null);

        using var refused = await RedeemAsync(
            client, discovery, ciba, authRequestId,
            [new(TokenRequest.Parameters.Resource, TestConstants.OtherApiResource)]);
        Assert.Equal(HttpStatusCode.BadRequest, refused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidTarget, (await ReadJsonAsync(refused))[ErrorResponse.Parameters.Error]?.GetValue<string>());

        using var granted = await RedeemAsync(
            client, discovery, ciba, authRequestId,
            [new(TokenRequest.Parameters.Resource, TestConstants.ApiResource)]);
        await AssertAnsweredAsync(granted);

        using var reused = await RedeemAsync(client, discovery, ciba, authRequestId, []);
        Assert.Equal(HttpStatusCode.BadRequest, reused.StatusCode);
        Assert.Equal(ErrorCodes.InvalidGrant, (await ReadJsonAsync(reused))[ErrorResponse.Parameters.Error]?.GetValue<string>());
    }

    /// <summary>
    /// Token requests redeeming one authenticated backchannel request at once, each of which would be issued tokens
    /// alone, are issued exactly one set: the others are refused as an invalid grant.
    /// </summary>
    [Fact]
    public async Task A_request_redeemed_by_concurrent_token_requests_is_redeemed_once()
    {
        const int requests = 8;
        await using var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var (ciba, authRequestId) = await AuthenticatedRequestAsync(
            host, client, discovery, Scopes.OpenId, grantedScope: null);

        var responses = await Task.WhenAll(Enumerable.Range(0, requests)
            .Select(_ => RedeemAsync(client, discovery, ciba, authRequestId, [])));
        try
        {
            Assert.Single(responses, response => response.StatusCode == HttpStatusCode.OK);
            foreach (var response in responses.Where(response => response.StatusCode != HttpStatusCode.OK))
            {
                Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
                Assert.Equal(
                    ErrorCodes.InvalidGrant,
                    (await ReadJsonAsync(response))[ErrorResponse.Parameters.Error]?.GetValue<string>());
            }
        }
        finally
        {
            foreach (var response in responses)
                response.Dispose();
        }
    }
}
