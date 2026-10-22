// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net;
using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.Model;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.Tokens.Revocation;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;
using RegistrationMembers = Abblix.Oidc.Server.Model.ClientRegistrationRequest.Parameters;
using RegistrationResponse = Abblix.Oidc.Server.Model.ClientRegistrationResponse.Parameters;
using ResponseParameters = Abblix.Oidc.Server.Endpoints.Authorization.Interfaces.AuthorizationResponse.Parameters;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <remarks>
/// A revocation recorded while a request waits for the end user refuses it in every delivery mode: a poll or ping
/// client is refused at the token endpoint, and a push client, which never comes there, is told access_denied in the
/// notification. Each case runs with a cutoff that does not reach the request as well, so a refusal is the
/// revocation's and not the host failing to issue anything at all.
/// </remarks>
public partial class BackChannelAuthenticationTests
{
    /// <summary>
    /// The end user revoked after the session the request completes with began is refused; a cutoff older than
    /// that session leaves it alone.
    /// </summary>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Poll, true)]
    [InlineData(BackchannelTokenDeliveryModes.Poll, false)]
    [InlineData(BackchannelTokenDeliveryModes.Ping, true)]
    [InlineData(BackchannelTokenDeliveryModes.Ping, false)]
    [InlineData(BackchannelTokenDeliveryModes.Push, true)]
    [InlineData(BackchannelTokenDeliveryModes.Push, false)]
    public async Task A_subject_revoked_after_the_session_began_is_refused_in_every_mode(string mode, bool cutoffAfterTheSession)
    {
        var deliveries = new NotificationRecorder();
        await using var host = CreateCibaHost(deliveries);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterAsync(mode, client, discovery);
        var authRequestId = await InitiateAsync(mode, client, discovery, ciba);

        var now = ClockOf(host).GetUtcNow();
        var sessionBegan = now.AddHours(-1);
        await RevokerOf(host).RevokeSubjectAsync(
            LoginHint,
            cutoffAfterTheSession ? now : sessionBegan.AddHours(-1),
            TestContext.Current.CancellationToken);

        await CompleteWithSessionAsync(host, authRequestId, sessionBegan, authorizedAt: null);

        await AssertOutcomeAsync(mode, refused: cutoffAfterTheSession, deliveries, client, discovery, ciba, authRequestId);
    }

    /// <summary>
    /// Consent withdrawn from the client refuses a request the end user approved before the withdrawal, and not one
    /// they approved after it, however old the session both complete with.
    /// </summary>
    [Theory]
    [InlineData(BackchannelTokenDeliveryModes.Poll, true)]
    [InlineData(BackchannelTokenDeliveryModes.Poll, false)]
    [InlineData(BackchannelTokenDeliveryModes.Ping, true)]
    [InlineData(BackchannelTokenDeliveryModes.Ping, false)]
    [InlineData(BackchannelTokenDeliveryModes.Push, true)]
    [InlineData(BackchannelTokenDeliveryModes.Push, false)]
    public async Task A_request_approved_before_a_revocation_at_its_client_is_refused_in_every_mode(string mode, bool approvedBeforeTheCutoff)
    {
        var deliveries = new NotificationRecorder();
        await using var host = CreateCibaHost(deliveries);
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterAsync(mode, client, discovery);
        var authRequestId = await InitiateAsync(mode, client, discovery, ciba);

        var now = ClockOf(host).GetUtcNow();
        var cutoff = now.AddMinutes(-30);
        await RevokerOf(host).RevokeSubjectAtClientAsync(
            LoginHint, ciba.ClientId, cutoff, TestContext.Current.CancellationToken);

        // The session predates the cutoff in both cases, so what decides is the approval moment alone: the host's
        // own when it set one, the completion's otherwise.
        await CompleteWithSessionAsync(
            host,
            authRequestId,
            sessionBegan: now.AddHours(-1),
            authorizedAt: approvedBeforeTheCutoff ? cutoff.AddMinutes(-15) : null);

        await AssertOutcomeAsync(mode, refused: approvedBeforeTheCutoff, deliveries, client, discovery, ciba, authRequestId);
    }

    private static Task<CibaClient> RegisterAsync(string mode, HttpClient client, DiscoveryDocument discovery)
    {
        switch (mode)
        {
            case BackchannelTokenDeliveryModes.Poll:
                return RegisterCibaClientAsync(client, discovery);

            case BackchannelTokenDeliveryModes.Ping:
                return RegisterPingCibaClientAsync(client, discovery);

            case BackchannelTokenDeliveryModes.Push:
                return RegisterPushCibaClientAsync(client, discovery);

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unexpected token delivery mode");
        }
    }

    /// <summary>
    /// Starts a request the way each mode's client does: a ping or push client presents the notification token the
    /// server must send back, and a push client the authorization_details its registration allows.
    /// </summary>
    private static Task<string> InitiateAsync(
        string mode, HttpClient client, DiscoveryDocument discovery, CibaClient ciba)
    {
        switch (mode)
        {
            case BackchannelTokenDeliveryModes.Poll:
                return InitiateAsync(client, discovery, ciba);

            case BackchannelTokenDeliveryModes.Ping:
                return InitiateAsync(client, discovery, ciba, authorizationDetails: null, NotificationToken);

            case BackchannelTokenDeliveryModes.Push:
                return InitiateAsync(client, discovery, ciba, RequestedDetails, NotificationToken);

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unexpected token delivery mode");
        }
    }

    /// <summary>
    /// Answers the stored request with a session that began at <paramref name="sessionBegan"/>, keeping what was
    /// requested as what is granted, and with the approval moment the host set, if any.
    /// </summary>
    private static async Task CompleteWithSessionAsync(
        WebApplicationFactory<Program> host,
        string authenticationRequestId,
        DateTimeOffset sessionBegan,
        DateTimeOffset? authorizedAt)
    {
        using var tenant = TestTenant.Enter(host.Services);
        using var scope = host.Services.CreateScope();
        var storage = scope.ServiceProvider.GetRequiredService<IBackChannelRequestStorage>();

        var stored = await storage.TryGetAsync(authenticationRequestId);
        Assert.NotNull(stored);

        var session = stored.AuthorizedGrant.AuthSession with { AuthenticationTime = sessionBegan };
        var completed = stored with
        {
            AuthorizedGrant = new AuthorizedGrant(session, stored.AuthorizedGrant.Context) { AuthorizedAt = authorizedAt },
        };
        completed.Status = BackChannelAuthenticationStatus.Authenticated;

        await scope.ServiceProvider
            .GetRequiredService<IAuthenticationCompletionHandler>()
            .CompleteAsync(authenticationRequestId, completed, TimeSpan.FromMinutes(5));
    }

    /// <summary>
    /// Reads the answer where each mode's client reads it: the token endpoint for poll and ping, the notification for
    /// push.
    /// </summary>
    private static async Task AssertOutcomeAsync(
        string mode,
        bool refused,
        NotificationRecorder deliveries,
        HttpClient client,
        DiscoveryDocument discovery,
        CibaClient ciba,
        string authRequestId)
    {
        switch (mode)
        {
            case BackchannelTokenDeliveryModes.Poll or BackchannelTokenDeliveryModes.Ping:
                var response = await RedeemAsync(client, discovery, ciba, authRequestId);
                var body = await ReadJsonAsync(response);
                if (refused)
                {
                    Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
                    Assert.Equal(ErrorCodes.InvalidGrant, body[ResponseParameters.Error]!.GetValue<string>());
                    Assert.Null(body[ResponseParameters.AccessToken]);
                    return;
                }

                Assert.True(response.IsSuccessStatusCode, $"the request should be redeemed, got {body}");
                Assert.False(string.IsNullOrEmpty(body[ResponseParameters.AccessToken]?.GetValue<string>()));
                return;

            case BackchannelTokenDeliveryModes.Push:
                var payload = Assert.Single(deliveries.Received).Payload;
                Assert.Equal(authRequestId, payload[BackChannelPushNotificationRequest.Parameters.AuthReqId]!.GetValue<string>());
                if (refused)
                {
                    Assert.Equal(
                        ErrorCodes.AccessDenied,
                        payload[BackChannelPushErrorNotificationRequest.Parameters.Error]!.GetValue<string>());
                    Assert.False(payload.ContainsKey(BackChannelPushNotificationRequest.Parameters.AccessToken));
                    return;
                }

                Assert.False(string.IsNullOrEmpty(
                    payload[BackChannelPushNotificationRequest.Parameters.AccessToken]?.GetValue<string>()));
                return;

            default:
                throw new ArgumentOutOfRangeException(nameof(mode), mode, "Unexpected token delivery mode");
        }
    }

    /// <summary>
    /// Registers a client that is told by a ping when its request completes and then redeems at the token endpoint.
    /// </summary>
    private static async Task<CibaClient> RegisterPingCibaClientAsync(HttpClient client, DiscoveryDocument discovery)
    {
        var registered = await RegisterClientAsync(client, discovery, new JsonObject
        {
            [RegistrationMembers.ClientName] = $"ciba-ping-{Guid.NewGuid():N}",
            [RegistrationMembers.ResponseTypes] = new JsonArray(),
            [RegistrationMembers.GrantTypes] = new JsonArray(GrantTypes.Ciba),
            [RegistrationMembers.TokenEndpointAuthMethod] = ClientAuthenticationMethods.ClientSecretPost,
            [RegistrationMembers.BackChannelTokenDeliveryMode] = BackchannelTokenDeliveryModes.Ping,
            [RegistrationMembers.BackChannelClientNotificationEndpoint] = NotificationEndpoint.AbsoluteUri,
        });

        return new CibaClient(
            registered[RegistrationResponse.ClientId]!.GetValue<string>(),
            registered[RegistrationResponse.ClientSecret]!.GetValue<string>());
    }

    private static ITokenRevoker RevokerOf(WebApplicationFactory<Program> host)
        => TestTenant.RevokerOf(host.Services);

    private static TimeProvider ClockOf(WebApplicationFactory<Program> host)
        => host.Services.GetRequiredService<TimeProvider>();
}
