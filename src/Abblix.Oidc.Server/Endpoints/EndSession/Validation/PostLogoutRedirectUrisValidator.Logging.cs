// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

partial class PostLogoutRedirectUrisValidator
{
    [LoggerMessage(
        EventId = LogEvents.Endpoints.PostLogoutRedirectUrisValidator.InvalidPostLogoutRedirectUri,
        Level = LogLevel.Warning,
        Message = "The post-logout redirect URI {RedirectUri} is invalid for client with id {ClientId}")]
    private partial void LogInvalidPostLogoutRedirectUri(Sanitized RedirectUri, string ClientId);
}
