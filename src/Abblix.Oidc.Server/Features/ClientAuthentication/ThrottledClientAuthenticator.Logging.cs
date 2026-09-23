// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.ClientAuthentication;

partial class ThrottledClientAuthenticator
{
    /// <summary>
    /// Names the address, because the operator's first question about a refusal like this is whether it is one
    /// sender or the one address a whole deployment shares.
    /// </summary>
    [LoggerMessage(
        EventId = LogEvents.RateLimiting.ThrottledClientAuthenticator.SourceRefused,
        Level = LogLevel.Warning,
        Message = "No credential was looked at: the source {Source} is over its budget of failed client authentications")]
    private partial void LogSourceRefused(Sanitized Source);
}
