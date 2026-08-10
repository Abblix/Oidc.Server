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
