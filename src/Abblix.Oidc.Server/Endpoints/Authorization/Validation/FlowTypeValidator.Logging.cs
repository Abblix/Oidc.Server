// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

partial class FlowTypeValidator
{
    [LoggerMessage(
        EventId = LogEvents.Endpoints.FlowTypeValidator.ResponseTypePartUnsupported,
        Level = LogLevel.Warning,
        Message = "The response type part {Part} is not supported by this server")]
    private partial void LogResponseTypePartUnsupported(string Part);

    [LoggerMessage(
        EventId = LogEvents.Endpoints.FlowTypeValidator.ResponseTypeNotAllowed,
        Level = LogLevel.Warning,
        Message = "The response type {@ResponseType} is not allowed for the client")]
    private partial void LogResponseTypeNotAllowed(string[]? ResponseType);

    [LoggerMessage(
        EventId = LogEvents.Endpoints.FlowTypeValidator.ResponseTypeInvalid,
        Level = LogLevel.Warning,
        Message = "The response type {@ResponseType} is not valid")]
    private partial void LogResponseTypeInvalid(string[]? ResponseType);
}
