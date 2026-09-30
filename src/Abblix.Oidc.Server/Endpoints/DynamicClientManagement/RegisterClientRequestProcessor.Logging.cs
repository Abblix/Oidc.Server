// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.DynamicClientManagement;

public partial class RegisterClientRequestProcessor
{
    [LoggerMessage(
        EventId = LogEvents.DynamicClientManagement.RegisterClientRequestProcessor.RegistrationNotKept,
        Level = LogLevel.Warning,
        Message = "The client with id {ClientId} is already registered")]
    private partial void LogRegistrationNotKept(Sanitized ClientId);
}
