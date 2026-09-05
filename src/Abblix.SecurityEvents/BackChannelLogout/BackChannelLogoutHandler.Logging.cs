// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Microsoft.Extensions.Logging;

namespace Abblix.SecurityEvents.BackChannelLogout;

partial class BackChannelLogoutHandler
{
    [LoggerMessage(
        EventId = LogEvents.BackChannelLogout.RequestRefused,
        Level = LogLevel.Warning,
        Message = "Back-channel logout refused: {Error} {Description}")]
    private partial void LogRefused(string error, string description);
}
