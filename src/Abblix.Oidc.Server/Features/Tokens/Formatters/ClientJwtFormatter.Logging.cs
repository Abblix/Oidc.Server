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
        EventId = LogEvents.TokenIssuance.ClientJwtFormatter.JwtNotIssued,
        Message = "No JWT issued to client {ClientId} ({Cause}): {Reason}")]
    private partial void LogJwtNotIssued(LogLevel level, string ClientId, ClientJwtRefusalCause Cause, string Reason);

    [LoggerMessage(
        EventId = LogEvents.TokenIssuance.ClientJwtFormatter.SigningKeyBelowTheFloor,
        Level = LogLevel.Error,
        Message = "The signing key {KeyId} is not used for {Algorithm}: it has {Bits} bits, below the {Floor} RFC 7518 requires")]
    private partial void LogSigningKeyBelowTheFloor(string? KeyId, string Algorithm, int Bits, int Floor);
}
