// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
