// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.Tokens;

partial class LogoutTokenService
{
    [LoggerMessage(
        EventId = LogEvents.Tokens.LogoutTokenService.TokenPrepared,
        Level = LogLevel.Debug,
        Message = "The logout token was prepared {@LogoutToken}")]
    private partial void LogTokenPrepared(JsonWebToken LogoutToken);
}
