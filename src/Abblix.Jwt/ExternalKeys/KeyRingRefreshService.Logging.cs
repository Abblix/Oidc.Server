// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

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
