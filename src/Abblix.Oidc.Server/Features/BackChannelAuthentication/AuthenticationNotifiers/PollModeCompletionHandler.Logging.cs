// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.BackChannelAuthentication.AuthenticationNotifiers;

partial class PollModeCompletionHandler
{
    [LoggerMessage(
        EventId = LogEvents.Device.PollModeCompletionHandler.TokensStored,
        Level = LogLevel.Debug,
        Message = "Poll mode - the authenticated request is stored for auth_req_id: {AuthReqId}. No " +
                  "token exists yet; they are minted at the token endpoint when the client redeems")]
    private partial void LogTokensStored(string AuthReqId);
}
