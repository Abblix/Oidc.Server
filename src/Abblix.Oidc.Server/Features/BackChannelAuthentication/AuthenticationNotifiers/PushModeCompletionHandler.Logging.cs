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
        Message = "CIBA push delivery failed for auth_req_id: {AuthReqId}; the authenticated request is retained until it expires")]
    private partial void LogPushDeliveryFailed(string AuthReqId);
}
