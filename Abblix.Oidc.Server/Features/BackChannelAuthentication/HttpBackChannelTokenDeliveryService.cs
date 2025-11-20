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
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication;

/// <summary>
/// HTTP-based implementation of backchannel token delivery service for CIBA push mode.
/// Sends HTTP POST requests to client endpoints with the complete token response.
/// </summary>
/// <param name="httpClientFactory">Factory for creating HTTP clients.</param>
/// <param name="logger">Logger for tracking delivery attempts and failures.</param>
public class HttpBackChannelTokenDeliveryService(
    IHttpClientFactory httpClientFactory,
    ILogger<HttpBackChannelTokenDeliveryService> logger) : IBackChannelTokenDeliveryService
{
    /// <summary>
    /// Delivers tokens to the client's registered endpoint via HTTP POST in CIBA push mode.
    /// </summary>
    /// <param name="clientNotificationEndpoint">The client's registered notification endpoint URL.</param>
    /// <param name="clientNotificationToken">Bearer token for authenticating the push request.</param>
    /// <param name="authenticationRequestId">The auth_req_id identifying the authentication request.</param>
    /// <param name="tokenResponse">The complete token response to deliver.</param>
    public async Task DeliverTokensAsync(
        Uri clientNotificationEndpoint,
        string clientNotificationToken,
        string authenticationRequestId,
        TokenIssued tokenResponse)
    {
        try
        {
            var httpClient = httpClientFactory.CreateClient(nameof(HttpBackChannelTokenDeliveryService));

            var pushPayload = new BackChannelTokenPushRequest
            {
                AuthenticationRequestId = authenticationRequestId,
                AccessToken = tokenResponse.AccessToken.EncodedJwt,
                TokenType = tokenResponse.TokenType,
                ExpiresIn = tokenResponse.ExpiresIn,
                IdToken = tokenResponse.IdToken?.EncodedJwt,
                RefreshToken = tokenResponse.RefreshToken?.EncodedJwt,
            };

            var request = new HttpRequestMessage(HttpMethod.Post, clientNotificationEndpoint);
            request.Headers.Add("Authorization", $"Bearer {clientNotificationToken}");
            request.Content = JsonContent.Create(pushPayload);

            logger.LogInformation(
                "Delivering tokens via CIBA push mode to {Endpoint} for auth_req_id: {AuthReqId}",
                clientNotificationEndpoint,
                authenticationRequestId);

            var response = await httpClient.SendAsync(request);

            if (response.IsSuccessStatusCode)
            {
                logger.LogInformation(
                    "Successfully delivered tokens via CIBA push mode for auth_req_id: {AuthReqId}",
                    authenticationRequestId);
            }
            else
            {
                logger.LogWarning(
                    "Failed to deliver tokens via CIBA push mode for auth_req_id: {AuthReqId}. Status: {StatusCode}",
                    authenticationRequestId,
                    response.StatusCode);
            }
        }
        catch (Exception ex)
        {
            logger.LogError(
                ex,
                "Error delivering tokens via CIBA push mode to {Endpoint} for auth_req_id: {AuthReqId}",
                clientNotificationEndpoint,
                authenticationRequestId);
        }
    }
}
