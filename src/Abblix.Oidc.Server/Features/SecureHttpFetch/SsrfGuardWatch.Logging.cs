// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

partial class SsrfGuardWatch
{
    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SsrfGuardWatch.ValidationReplaced,
        Level = LogLevel.Warning,
        Message = "HTTP client '{ClientName}' was registered with SSRF address validation, and its primary handler "
            + "is now {PrimaryHandler}. Requests on this client address a URI supplied by an OAuth client, and that "
            + "address is no longer validated before each attempt. Configure the handler the validation wraps "
            + "instead of replacing it, or silence this message by its own log category if the change was intended.")]
    private partial void LogValidationReplaced(string clientName, string primaryHandler);
}
