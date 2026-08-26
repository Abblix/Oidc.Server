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
                  "are gone - nothing retries them. What is left in storage reads Authenticated and " +
                  "still carries what the client asked for rather than what the end user approved, so " +
                  "it cannot be completed again: recovering means asking the end user, not resending " +
                  "from this record. It expires on its own.")]
    private partial void LogPushDeliveryFailed(string AuthReqId);

    /// <summary>
    /// The validator's own words, which the client never sees.
    /// </summary>
    /// <remarks>
    /// A refusal here names a HOST-side defect: the end user approved something the deployment will not
    /// issue, so whoever has to fix it is an operator rather than the client. The client is told nothing
    /// at all, because a push outcome travels through a notification endpoint this server sends no error
    /// payload to - which is why this record is the only account of the refusal anybody gets.
    /// </remarks>
    [LoggerMessage(
        EventId = LogEvents.Device.PushModeCompletionHandler.GrantedAuthorizationDetailsRefused,
        Level = LogLevel.Warning,
        Message = "The per-type validators will not issue the authorization_details completing " +
                  "auth_req_id {AuthReqId}, so it is refused. ClientId: {ClientId}, reason: {Reason}")]
    private partial void LogGrantedAuthorizationDetailsRefused(
        string AuthReqId, string ClientId, string Reason);
}
