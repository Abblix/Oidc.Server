// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.UserInfo;

partial class UserClaimsProvider
{
    [LoggerMessage(
        EventId = LogEvents.Misc.UserClaimsProvider.UserClaimsNotFound,
        Level = LogLevel.Warning,
        Message = "The user claims were not found by subject value")]
    private partial void LogUserClaimsNotFound();

    [LoggerMessage(
        EventId = LogEvents.Misc.UserClaimsProvider.MissingClaims,
        Level = LogLevel.Warning,
        Message = "The following claims are requested, but not returned from {IUserInfoProvider}: {@MissingClaims}")]
    private partial void LogMissingClaims(string? IUserInfoProvider, string[] MissingClaims);
}
