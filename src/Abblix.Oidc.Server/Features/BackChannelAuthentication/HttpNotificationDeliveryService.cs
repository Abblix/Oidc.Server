// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Http.Json;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// HTTP-based implementation of backchannel notification service for CIBA ping and push modes.
/// Sends HTTP POST notifications to client endpoints with authentication request status updates or token delivery.
/// </summary>
/// <remarks>
/// Delivery is a single attempt, deliberately: a notification is best-effort, and what a failed one costs is the
/// client waiting out its own timeout rather than a lost protocol state. A deployment that wants more configures the
/// named client - see <see cref="BackChannelNotificationTransport.HttpClientName"/> - and gets retries without this
/// type holding any state.
/// </remarks>
/// <param name="logger">Logger for tracking notification attempts and failures.</param>
/// <param name="httpClientFactory">Factory for creating HTTP clients.</param>
public partial class HttpNotificationDeliveryService(
    ILogger<HttpNotificationDeliveryService> logger,
    IHttpClientFactory httpClientFactory) : INotificationDeliveryService
{
    /// <summary>
    /// Sends an HTTP POST notification to the client's registered endpoint.
    /// </summary>
    /// <param name="clientNotificationEndpoint">The client's registered notification endpoint URL.</param>
    /// <param name="clientNotificationToken">Bearer token for authenticating the notification request.</param>
    /// <param name="payload">The notification payload to send.</param>
    /// <param name="mode">The CIBA mode (ping or push) for logging purposes.</param>
    /// <returns><c>true</c> if the endpoint returned a success status; otherwise <c>false</c>.</returns>
    public async Task<bool> SendAsync(
        Uri clientNotificationEndpoint,
        string clientNotificationToken,
        IBackChannelNotificationRequest payload,
        string mode)
    {
        try
        {
            var httpClient = httpClientFactory.CreateClient(BackChannelNotificationTransport.HttpClientName);

            var request = new HttpRequestMessage(HttpMethod.Post, clientNotificationEndpoint);
            request.AddBearerToken(clientNotificationToken);
            request.Content = JsonContent.Create(payload, payload.GetType());

            LogSendingNotification(mode, clientNotificationEndpoint);

            var response = await httpClient.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                LogNotificationSucceeded(mode);
                return true;
            }

            LogNotificationFailed(mode, response.StatusCode);
            return false;
        }
        catch (Exception ex)
        {
            LogNotificationError(ex, mode, clientNotificationEndpoint);
            return false;
        }
    }
}
