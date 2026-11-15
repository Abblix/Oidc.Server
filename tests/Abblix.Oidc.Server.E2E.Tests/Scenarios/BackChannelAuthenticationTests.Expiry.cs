// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using System.Net;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Model;
using Xunit;
using CibaParameters = Abblix.Oidc.Server.Model.BackChannelAuthenticationRequest.Parameters;
using CibaResponse = Abblix.Oidc.Server.Model.BackChannelAuthenticationSuccess.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <remarks>
/// Driven against the real request storage and the real clock, since what decides the answer is whether the store
/// still holds the request once its expires_in has passed.
/// </remarks>
public partial class BackChannelAuthenticationTests
{
    /// <summary>
    /// The lifetime the request asks for, short enough to wait out.
    /// </summary>
    private static readonly TimeSpan ShortRequestedExpiry = TimeSpan.FromSeconds(3);

    /// <summary>
    /// CIBA Core 1.0 section 11: expired_token, "The auth_req_id has expired. The Client will need to make a new
    /// Authentication Request". A request polled after its expires_in is answered so, while the same expired
    /// auth_req_id polled by another client is still invalid_grant: "If the auth_req_id is invalid or was issued to
    /// another Client, an invalid_grant error MUST be returned".
    /// </summary>
    [Fact]
    public async Task An_auth_req_id_polled_after_its_expiry_is_answered_expired_token()
    {
        await using var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var initiator = await RegisterCibaClientAsync(client, discovery);
        var bystander = await RegisterCibaClientAsync(client, discovery);

        var initiated = await FormPostHelpers.PostFormAsync(
            client,
            discovery.BackChannelAuthenticationEndpoint!,
            new Dictionary<string, string>
            {
                [CibaParameters.Scope] = Scopes.OpenId,
                [CibaParameters.LoginHint] = LoginHint,
                [CibaParameters.RequestedExpiry] =
                    ((int)ShortRequestedExpiry.TotalSeconds).ToString(CultureInfo.InvariantCulture),
                [ClientRequest.Parameters.ClientId] = initiator.ClientId,
                [ClientRequest.Parameters.ClientSecret] = initiator.ClientSecret,
            });
        var acknowledgement = await ReadJsonAsync(initiated);
        Assert.True(initiated.IsSuccessStatusCode, $"{(int)initiated.StatusCode}: {acknowledgement}");
        Assert.Equal(
            (int)ShortRequestedExpiry.TotalSeconds,
            acknowledgement[CibaResponse.ExpiresIn]!.GetValue<int>());
        var authRequestId = acknowledgement[CibaResponse.AuthenticationRequestId]!.GetValue<string>();

        await Task.Delay(ShortRequestedExpiry + TimeSpan.FromMilliseconds(200), TestContext.Current.CancellationToken);

        var byBystander = await RedeemAsync(client, discovery, bystander, authRequestId);
        var bystanderBody = await ReadJsonAsync(byBystander);
        Assert.Equal(HttpStatusCode.BadRequest, byBystander.StatusCode);
        Assert.Equal(ErrorCodes.InvalidGrant, bystanderBody[ErrorResponse.Parameters.Error]!.GetValue<string>());

        var byInitiator = await RedeemAsync(client, discovery, initiator, authRequestId);
        var initiatorBody = await ReadJsonAsync(byInitiator);
        Assert.Equal(HttpStatusCode.BadRequest, byInitiator.StatusCode);
        Assert.Equal(ErrorCodes.ExpiredToken, initiatorBody[ErrorResponse.Parameters.Error]!.GetValue<string>());
    }
}
