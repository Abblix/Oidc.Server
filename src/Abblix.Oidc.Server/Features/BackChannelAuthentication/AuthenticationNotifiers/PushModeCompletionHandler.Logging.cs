// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

partial class PushModeCompletionHandler
{
    [LoggerMessage(
        EventId = LogEvents.Device.PushModeCompletionHandler.GeneratingTokens,
        Level = LogLevel.Information,
        Message = "Generating and delivering tokens via CIBA push mode for auth_req_id: {AuthReqId}")]
    private partial void LogGeneratingTokens(string AuthReqId);

    [LoggerMessage(
        EventId = LogEvents.Device.PushModeCompletionHandler.TokensDelivered,
        Level = LogLevel.Information,
        Message = "Tokens delivered via CIBA push mode for auth_req_id: {AuthReqId}")]
    private partial void LogTokensDelivered(string AuthReqId);

    [LoggerMessage(
        EventId = LogEvents.Device.PushModeCompletionHandler.TokenGenerationFailed,
        Level = LogLevel.Error,
        Message = "Failed to generate tokens for CIBA push mode, auth_req_id: {AuthReqId}, Error: {ErrorCode}")]
    private partial void LogTokenGenerationFailed(string AuthReqId, string ErrorCode);

    [LoggerMessage(
        EventId = LogEvents.Device.PushModeCompletionHandler.PushDeliveryFailed,
        Level = LogLevel.Warning,
        Message = "CIBA push delivery failed for auth_req_id: {AuthReqId}. The tokens were minted and " +
                  "are gone - nothing retries them, and the request was taken before minting, so nothing " +
                  "is left to complete again: recovering means asking the end user.")]
    private partial void LogPushDeliveryFailed(string AuthReqId);

    /// <summary>
    /// The validator's own words, which the client never sees.
    /// </summary>
    /// <remarks>
    /// The grant holds an entry wider than the request or one the deployment will not issue, and whoever has
    /// to act on it is an operator rather than the client. The client is sent access_denied with a fixed
    /// description, never these words - which is why this record is the only account of the reason anybody
    /// gets.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.PushModeCompletionHandler.GrantedAuthorizationDetailsRefused,
        Level = LogLevel.Warning,
        Message = "The per-type validators will not issue the authorization_details completing " +
                  "auth_req_id {AuthReqId}, so it is refused. ClientId: {ClientId}, reason: {Reason}")]
    private partial void LogGrantedAuthorizationDetailsRefused(
        string AuthReqId, string ClientId, string Reason);

    /// <summary>
    /// The check of the granted authorization_details failed with an exception, a fault in the host's code,
    /// and the client was told the transaction failed.
    /// </summary>
    [LoggerMessage(
        EventId = LogEvents.Device.PushModeCompletionHandler.GrantedAuthorizationDetailsFaulted,
        Level = LogLevel.Error,
        Message = "Checking the authorization_details completing auth_req_id {AuthReqId} failed, so the " +
                  "client was told the transaction failed. ClientId: {ClientId}")]
    private partial void LogGrantedAuthorizationDetailsFaulted(
        Exception exception, string AuthReqId, string ClientId);

    /// <summary>
    /// Issuing the tokens of a taken push request threw, and the client was told the transaction failed.
    /// </summary>
    [LoggerMessage(
        EventId = LogEvents.Device.PushModeCompletionHandler.TokenIssuanceFaulted,
        Level = LogLevel.Error,
        Message = "Issuing the tokens of auth_req_id {AuthReqId} failed, so the client was told the transaction " +
                  "failed. ClientId: {ClientId}")]
    private partial void LogTokenIssuanceFaulted(Exception exception, string AuthReqId, string ClientId);
}
