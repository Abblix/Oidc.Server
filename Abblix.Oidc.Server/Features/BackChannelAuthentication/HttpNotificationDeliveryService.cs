// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net.Http.Json;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// HTTP-based implementation of backchannel notification service for CIBA ping and push modes.
/// Sends HTTP POST notifications to client endpoints with authentication request status updates or token delivery.
/// </summary>
/// <param name="httpClientFactory">Factory for creating HTTP clients.</param>
/// <param name="logger">Logger for tracking notification attempts and failures.</param>
public class HttpNotificationDeliveryService(
    IHttpClientFactory httpClientFactory,
    ILogger<HttpNotificationDeliveryService> logger) : INotificationDeliveryService
{
    /// <summary>
    /// Sends an HTTP POST notification to the client's registered endpoint.
    /// </summary>
    /// <param name="clientNotificationEndpoint">The client's registered notification endpoint URL.</param>
    /// <param name="clientNotificationToken">Bearer token for authenticating the notification request.</param>
    /// <param name="payload">The notification payload to send.</param>
    /// <param name="mode">The CIBA mode (ping or push) for logging purposes.</param>
    public async Task SendAsync(
        Uri clientNotificationEndpoint,
        string clientNotificationToken,
        IBackChannelNotificationRequest payload,
        string mode)
    {
        try
        {
            var httpClient = httpClientFactory.CreateClient(nameof(HttpNotificationDeliveryService));

            var request = new HttpRequestMessage(HttpMethod.Post, clientNotificationEndpoint);
            request.AddBearerToken(clientNotificationToken);
            request.Content = JsonContent.Create(payload, payload.GetType());

            logger.LogInformation(
                "Sending CIBA {Mode} notification to {Endpoint}",
                mode,
                clientNotificationEndpoint);

            var response = await httpClient.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                logger.LogInformation("Successfully sent CIBA {Mode} notification", mode);
            }
            else
            {
                logger.LogWarning("Failed to send CIBA {Mode} notification. Status: {StatusCode}", mode, response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "Error sending CIBA {Mode} notification to {Endpoint}",
                mode,
                clientNotificationEndpoint);
        }
    }
}
