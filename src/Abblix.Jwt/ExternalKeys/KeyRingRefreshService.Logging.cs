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

namespace Abblix.Jwt.ExternalKeys;

partial class KeyRingRefreshService
{
    [LoggerMessage(
        EventId = LogEvents.KeyRing.RefreshFailed,
        Level = LogLevel.Error,
        Message = "Refreshing the key ring failed; the server keeps serving the keys it already holds and will " +
                  "retry in {RetryIn}. Until a refresh succeeds it announces no key another instance has minted " +
                  "since, so a rotation completed during the outage will produce tokens this instance cannot " +
                  "verify.")]
    private partial void LogRefreshFailed(Exception exception, TimeSpan retryIn);
}
