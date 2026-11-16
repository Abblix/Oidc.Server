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
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using StoredRequest = Abblix.Oidc.Server.Features.BackChannelAuthentication.BackChannelAuthenticationRequest;
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

        var authRequestId = await InitiateShortLivedAsync(client, discovery, initiator);

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

    /// <summary>
    /// The answer to an expired auth_req_id does not depend on how late the poll comes. A ping client polls when it is
    /// notified, and CIBA Core 1.0 section 10.2 needs no notification sent for an expired request, so its last poll can
    /// come well after a short expiry: polled at more than twice its expires_in, the request is still answered
    /// expired_token rather than as one never issued.
    /// </summary>
    [Fact]
    public async Task An_auth_req_id_polled_long_after_a_short_expiry_is_answered_expired_token()
    {
        await using var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var initiator = await RegisterCibaClientAsync(client, discovery);

        var authRequestId = await InitiateShortLivedAsync(client, discovery, initiator);

        var early = await RedeemAsync(client, discovery, initiator, authRequestId);
        var earlyBody = await ReadJsonAsync(early);
        Assert.Equal(ErrorCodes.AuthorizationPending, earlyBody[ErrorResponse.Parameters.Error]!.GetValue<string>());

        await Task.Delay(
            ShortRequestedExpiry + ShortRequestedExpiry + ShortRequestedExpiry / 2,
            TestContext.Current.CancellationToken);

        var late = await RedeemAsync(client, discovery, initiator, authRequestId);
        var lateBody = await ReadJsonAsync(late);
        Assert.Equal(HttpStatusCode.BadRequest, late.StatusCode);
        Assert.Equal(ErrorCodes.ExpiredToken, lateBody[ErrorResponse.Parameters.Error]!.GetValue<string>());
    }

    /// <summary>
    /// CIBA Core 1.0 section 7.3, on expires_in: "A Client calling the token endpoint with an expired auth_req_id will
    /// receive an error". The end user approving in time does not stretch that lifetime: a request approved at once,
    /// with the host keeping the approval readable for minutes and naming a later expiry on its own copy, and polled
    /// after its expires_in, is answered expired_token and issues no token.
    /// </summary>
    [Fact]
    public async Task An_auth_req_id_approved_in_time_and_polled_after_its_expiry_issues_no_token()
    {
        await using var host = CreateCibaHost();
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var initiator = await RegisterCibaClientAsync(client, discovery);

        var authRequestId = await InitiateShortLivedAsync(client, discovery, initiator);
        await ApproveAsync(host, authRequestId);

        await Task.Delay(ShortRequestedExpiry + TimeSpan.FromMilliseconds(500), TestContext.Current.CancellationToken);

        var response = await RedeemAsync(client, discovery, initiator, authRequestId);
        var body = await ReadJsonAsync(response);
        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Equal(ErrorCodes.ExpiredToken, body[ErrorResponse.Parameters.Error]?.GetValue<string>());
        Assert.Null(body[TokenResponse.Parameters.AccessToken]);
    }

    /// <summary>
    /// How long the host keeps an approval readable, far past the request's own expiry.
    /// </summary>
    private static readonly TimeSpan ApprovalKeptFor = TimeSpan.FromMinutes(5);

    /// <summary>
    /// Starts a backchannel authentication asking for <see cref="ShortRequestedExpiry"/>, asserting it was granted.
    /// </summary>
    private static async Task<string> InitiateShortLivedAsync(
        HttpClient client, DiscoveryDocument discovery, CibaClient ciba)
    {
        var initiated = await FormPostHelpers.PostFormAsync(
            client,
            discovery.BackChannelAuthenticationEndpoint!,
            new Dictionary<string, string>
            {
                [CibaParameters.Scope] = Scopes.OpenId,
                [CibaParameters.LoginHint] = LoginHint,
                [CibaParameters.RequestedExpiry] =
                    ((int)ShortRequestedExpiry.TotalSeconds).ToString(CultureInfo.InvariantCulture),
                [ClientRequest.Parameters.ClientId] = ciba.ClientId,
                [ClientRequest.Parameters.ClientSecret] = ciba.ClientSecret,
            });
        var acknowledgement = await ReadJsonAsync(initiated);
        Assert.True(initiated.IsSuccessStatusCode, $"{(int)initiated.StatusCode}: {acknowledgement}");
        Assert.Equal(
            (int)ShortRequestedExpiry.TotalSeconds,
            acknowledgement[CibaResponse.ExpiresIn]!.GetValue<int>());
        return acknowledgement[CibaResponse.AuthenticationRequestId]!.GetValue<string>();
    }

    /// <summary>
    /// The end user approving the request as asked, through the completion seam a host calls, with a host copy that
    /// names its own later expiry.
    /// </summary>
    private static async Task ApproveAsync(WebApplicationFactory<Program> host, string authenticationRequestId)
    {
        using var tenant = TestTenant.Enter(host.Services);
        using var scope = host.Services.CreateScope();
        var storage = scope.ServiceProvider.GetRequiredService<IBackChannelRequestStorage>();

        var stored = await storage.TryGetAsync(TestTenant.Of(host.Services), authenticationRequestId);
        Assert.NotNull(stored);

        var clock = scope.ServiceProvider.GetRequiredService<TimeProvider>();
        var session = new AuthSession(
            Subject: LoginHint,
            SessionId: Guid.NewGuid().ToString("N"),
            AuthenticationTime: clock.GetUtcNow(),
            IdentityProvider: "e2e-test");

        var approved = new StoredRequest(
            new AuthorizedGrant(session, stored.AuthorizedGrant.Context), clock.GetUtcNow() + ApprovalKeptFor)
        {
            Status = BackChannelAuthenticationStatus.Authenticated,
        };

        await scope.ServiceProvider
            .GetRequiredService<IAuthenticationCompletionHandler>()
            .CompleteAsync(TestTenant.Of(host.Services), authenticationRequestId, approved, ApprovalKeptFor);
    }
}
