// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ReplayPrevention;

partial class ConfiguredReplayCache
{
    [LoggerMessage(
        EventId = LogEvents.Tokens.DistributedJwtReplayCache.ReplayDetected,
        Level = LogLevel.Debug,
        Message = "JWT replay detected for jti {JwtId}")]
    private partial void LogReplayDetected(string JwtId);

    [LoggerMessage(
        EventId = LogEvents.Tokens.DistributedJwtReplayCache.MarkedAsUsed,
        Level = LogLevel.Debug,
        Message = "Marked jti {JwtId} as used, remembered until {ExpiresAt}")]
    private partial void LogMarkedAsUsed(string JwtId, DateTimeOffset ExpiresAt);
}
