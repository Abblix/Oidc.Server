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

partial class NoneClientAuthenticator
{
    [LoggerMessage(
        EventId = LogEvents.ClientAuth.NoneClientAuthenticator.ClientNotFound,
        Level = LogLevel.Debug,
        Message = "Client authentication failed: Client information with id {ClientId} is missing")]
    private partial void LogClientNotFound(Sanitized ClientId);
}
