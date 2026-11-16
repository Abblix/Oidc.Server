// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.UserInfo;

partial class FapiInteractionIdResolver
{
    [LoggerMessage(
        EventId = LogEvents.Misc.FapiInteractionIdResolver.InteractionIdAnswered,
        Level = LogLevel.Information,
        Message = "UserInfo answered under x-fapi-interaction-id {InteractionId}")]
    private partial void LogInteractionIdAnswered(string interactionId);

    [LoggerMessage(
        EventId = LogEvents.Misc.FapiInteractionIdResolver.MalformedInteractionIdReplaced,
        Level = LogLevel.Warning,
        Message = "The x-fapi-interaction-id received is not a UUID and was replaced by {InteractionId}")]
    private partial void LogMalformedInteractionIdReplaced(string interactionId);
}
