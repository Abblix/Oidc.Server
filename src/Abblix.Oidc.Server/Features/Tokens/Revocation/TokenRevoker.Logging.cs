// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Tokens.Revocation;

partial class TokenRevoker
{
    // The principal is deliberately absent: it is a subject or a session identifier, and this line is
    // written on every suspension. What an operator needs from it is that a revocation happened, how far
    // back it reaches and how long it will hold - the identity is in whatever asked for the revocation.
    [LoggerMessage(
        EventId = LogEvents.Revocation.TokenRevoker.CutoffRecorded,
        Level = LogLevel.Information,
        Message = "Recorded a {Scope} revocation cutoff at {Cutoff}, kept until {ExpiresAt}")]
    private partial void LogCutoffRecorded(RevocationScope Scope, DateTimeOffset Cutoff, DateTimeOffset ExpiresAt);
}
