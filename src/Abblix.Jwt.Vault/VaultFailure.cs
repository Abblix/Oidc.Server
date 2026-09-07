// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using Abblix.Jwt.ExternalKeys;

namespace Abblix.Jwt.Vault;

/// <summary>
/// Decides which of the library's two custodian failures a Vault answer is, so an endpoint can say whether the
/// caller should come back. Only this package can make that call: the endpoint sees an exception, and the status
/// that separates "sealed, try again" from "your token may not do that" is Vault's alone.
/// </summary>
internal static class VaultFailure
{
    /// <summary>
    /// Whether a status is one that a later attempt may find cleared. A sealed Vault answers 503, a standby
    /// replica 429, and an unsealed server having a bad time answers 5xx; none of those is about the request.
    /// Everything else - a rejected token, a denied path, a key that is not there - meets the same answer next
    /// time, so it is not offered a retry.
    /// </summary>
    internal static bool IsTransient(HttpStatusCode status)
        => status is HttpStatusCode.TooManyRequests or >= HttpStatusCode.InternalServerError;

    /// <summary>
    /// Whether a failure that never reached Vault may cure itself: a connection error, the client's own timeout
    /// (which arrives as cancellation while the caller's token is not cancelled), or a credential file that
    /// cannot be read at this moment. The same reading <see cref="LoginClient"/> applies to its retry loop.
    /// </summary>
    internal static bool IsTransientTransport(Exception exception, CancellationToken cancellationToken)
        => exception switch
        {
            HttpRequestException => true,
            IOException => true,
            OperationCanceledException => !cancellationToken.IsCancellationRequested,
            _ => false,
        };
}
