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

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

partial class ResponseModeValidator
{
    [LoggerMessage(
        EventId = LogEvents.Endpoints.ResponseModeValidator.IncompatibleResponseMode,
        Level = LogLevel.Warning,
        Message = "The response mode {ResponseMode} is not compatible with response type {ResponseType}")]
    private partial void LogIncompatibleResponseMode(string ResponseMode, string[]? ResponseType);

    [LoggerMessage(
        EventId = LogEvents.Endpoints.ResponseModeValidator.ResponseModeNotAllowedForClient,
        Level = LogLevel.Warning,
        Message = "The response mode {ResponseMode} is not allowed for the client {ClientId}")]
    private partial void LogResponseModeNotAllowedForClient(string ResponseMode, string ClientId);
}
