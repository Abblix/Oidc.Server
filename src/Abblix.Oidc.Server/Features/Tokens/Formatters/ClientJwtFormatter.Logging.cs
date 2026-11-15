// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

partial class ClientJwtFormatter
{
    [LoggerMessage(
        EventId = LogEvents.Tokens.ClientJwtFormatter.JwtNotIssued,
        Message = "No JWT issued to client {ClientId} ({Cause}): {Reason}")]
    private partial void LogJwtNotIssued(LogLevel level, string ClientId, ClientJwtRefusalCause Cause, string Reason);
}
