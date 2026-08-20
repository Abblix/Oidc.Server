// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Oidc.Server.Features.SecureHttpFetch;

partial class SecureUriValidator
{
    [LoggerMessage(
        EventId = LogEvents.HttpFetch.SecureUriValidator.SchemeRestrictionLifted,
        Level = LogLevel.Warning,
        Message = "SecureHttpFetchOptions.AllowedSchemes is an empty list, which lifts the URI scheme restriction "
            + "entirely: SSRF-guarded fetches may use any scheme, including plain HTTP. Client-supplied addresses "
            + "such as key sets and back-channel logout endpoints are fetched under this policy. State the schemes "
            + "you accept, or silence this message by its own log category if the lifted restriction is intended.")]
    private static partial void LogSchemeRestrictionLifted(ILogger logger);
}
