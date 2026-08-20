// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Utils;
using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

partial class RedirectUriValidator
{
    [LoggerMessage(
        EventId = LogEvents.Endpoints.RedirectUriValidator.InvalidRedirectUri,
        Level = LogLevel.Warning,
        Message = "The redirect URI {RedirectUri} is invalid for client with id {ClientId}")]
    private partial void LogInvalidRedirectUri(Sanitized RedirectUri, string ClientId);
}
