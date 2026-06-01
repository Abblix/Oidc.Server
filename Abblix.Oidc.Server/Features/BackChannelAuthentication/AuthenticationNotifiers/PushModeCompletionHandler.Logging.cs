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
