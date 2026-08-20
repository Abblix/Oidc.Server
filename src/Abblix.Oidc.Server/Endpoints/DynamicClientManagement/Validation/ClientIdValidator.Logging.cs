// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Validation;

partial class ClientIdValidator
{
    [LoggerMessage(
        EventId = LogEvents.DynamicClientManagement.ClientIdValidator.ClientNotFound,
        Level = LogLevel.Warning,
        Message = "The client with id {ClientId} does not exist")]
    private partial void LogClientNotFound(Sanitized ClientId);

    [LoggerMessage(
        EventId = LogEvents.DynamicClientManagement.ClientIdValidator.ClientAlreadyRegistered,
        Level = LogLevel.Warning,
        Message = "The client with id {ClientId} is already registered")]
    private partial void LogClientAlreadyRegistered(Sanitized ClientId);
}
