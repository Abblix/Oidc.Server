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
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// HTTP-based implementation of backchannel notification service for CIBA ping mode.
/// Sends HTTP POST notifications to client endpoints with authentication request status updates.
/// </summary>
/// <param name="httpClientFactory">Factory for creating HTTP clients.</param>
/// <param name="logger">Logger for tracking notification attempts and failures.</param>
public class HttpBackChannelNotificationService(
    IHttpClientFactory httpClientFactory,
    ILogger<HttpBackChannelNotificationService> logger) : IBackChannelNotificationService
{
    /// <summary>
    /// Sends an HTTP POST notification to the client's registered endpoint.
    /// </summary>
    /// <param name="clientNotificationEndpoint">The client's registered notification endpoint URL.</param>
    /// <param name="clientNotificationToken">Bearer token for authenticating the notification request.</param>
    /// <param name="authenticationRequestId">The auth_req_id identifying the authentication request.</param>
    public async Task NotifyAsync(
        Uri clientNotificationEndpoint,
        string clientNotificationToken,
        string authenticationRequestId)
    {
        try
        {
            var httpClient = httpClientFactory.CreateClient(nameof(HttpBackChannelNotificationService));

            var notification = new BackChannelNotificationRequest
            {
                AuthenticationRequestId = authenticationRequestId,
            };

            var request = new HttpRequestMessage(HttpMethod.Post, clientNotificationEndpoint);
            request.Headers.Add("Authorization", $"Bearer {clientNotificationToken}");
            request.Content = JsonContent.Create(notification);

            logger.LogInformation(
                "Sending CIBA ping notification to {Endpoint} for auth_req_id: {AuthReqId}",
                clientNotificationEndpoint,
                authenticationRequestId);

            var response = await httpClient.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                logger.LogInformation(
                    "Successfully sent CIBA ping notification for auth_req_id: {AuthReqId}",
                    authenticationRequestId);
            }
            else
            {
                logger.LogWarning(
                    "Failed to send CIBA ping notification for auth_req_id: {AuthReqId}. Status: {StatusCode}",
                    authenticationRequestId,
                    response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "Error sending CIBA ping notification to {Endpoint} for auth_req_id: {AuthReqId}",
                clientNotificationEndpoint,
                authenticationRequestId);
        }
    }

    /// <summary>
    /// Represents the notification payload sent to the client in ping mode.
    /// </summary>
    private record BackChannelNotificationRequest
    {
        /// <summary>
        /// The authentication request identifier that is ready for token retrieval.
        /// </summary>
        public required string AuthenticationRequestId { get; init; }
    }
}
