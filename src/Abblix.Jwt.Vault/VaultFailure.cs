// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// Whether a status is one that a later attempt may find cleared. A sealed server answers 503 and one
    /// having a bad time answers 5xx; 429 is the lease-quota refusal, which the next request may pass; and 412
    /// is the answer Vault documents as "should be retried, perhaps with a little wait" - data this node has
    /// not caught up on yet. None of those is about the request. Everything else - a rejected token, a denied
    /// path, a key that is not there - meets the same answer next time, so it is not offered a retry.
    /// </summary>
    /// <remarks>
    /// The standby and replication codes Vault also defines belong to its health endpoint, which this package
    /// never calls, so they are not read here. Naming them would describe a path the custodian does not take.
    /// </remarks>
    internal static bool IsTransient(HttpStatusCode status)
        => status is HttpStatusCode.TooManyRequests
            or HttpStatusCode.PreconditionFailed
            or >= HttpStatusCode.InternalServerError;

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
