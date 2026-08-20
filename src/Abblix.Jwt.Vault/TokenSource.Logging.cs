// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Logging;

namespace Abblix.Jwt.Vault;

internal sealed partial class TokenSource
{
    [LoggerMessage(LogEvents.TokenLifecycle.LeaseStoppedExtending, LogLevel.Information,
        "The renewed lease ({RenewedLease}) no longer reaches the full length a login grants " +
        "({FullLease}) - the maximum TTL is close; logging in afresh while the token is still valid")]
    private partial void LogLeaseStoppedExtending(TimeSpan renewedLease, TimeSpan fullLease);

    [LoggerMessage(LogEvents.TokenLifecycle.NonExpiringToken, LogLevel.Warning,
        "The login produced a token without an expiry; nothing to refresh. Production roles should issue " +
        "expiring tokens")]
    private partial void LogNonExpiringToken();

    [LoggerMessage(LogEvents.TokenLifecycle.UnexpectedFailure, LogLevel.Error,
        "The token refresh hit a failure it did not foresee; a backoff window is open and the next " +
        "request past it will retry")]
    private partial void LogUnexpectedFailure(Exception exception);
}
