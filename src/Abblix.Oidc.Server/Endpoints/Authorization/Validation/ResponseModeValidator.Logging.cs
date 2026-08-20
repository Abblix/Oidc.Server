// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
