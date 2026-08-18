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
