// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using Abblix.Jwt.ExternalKeys;
using Azure;

namespace Abblix.Jwt.Azure;

/// <summary>
/// Decides which of the library's two custodian failures a Key Vault answer is, so an endpoint can say whether
/// the caller should come back. Only this package can make that call: the endpoint sees an exception, and the
/// status that separates "the vault is busy" from "this identity may not do that" is the service's alone.
/// </summary>
internal static class AzureFailure
{
    /// <summary>
    /// Whether a status is one that a later attempt may find cleared. Key Vault throttles per vault and says so
    /// with 429, and a service having a bad time answers 5xx; neither is about the request. A 401 or 403 is a
    /// grant that is missing, a 404 a key that is not there, and a 400 a request that was wrong - all of which
    /// meet the same answer next time.
    /// </summary>
    internal static bool IsTransient(int status)
        => status is (int)HttpStatusCode.TooManyRequests or >= (int)HttpStatusCode.InternalServerError;

    /// <summary>
    /// Reports a Key Vault failure as one of the two, so it arrives at an endpoint that can read it. Anything
    /// that is not the service answering - a connection that could not be made, the SDK's own timeout - is
    /// temporary as well, for the same reason: it says nothing about the request.
    /// </summary>
    /// <param name="operation">What was being asked of the vault, named for the log line.</param>
    /// <param name="call">The call.</param>
    /// <param name="cancellationToken">The caller's token, which tells its cancellation apart from a timeout of
    /// ours.</param>
    internal static async Task<T> Classified<T>(
        string operation,
        Func<Task<T>> call,
        CancellationToken cancellationToken)
    {
        try
        {
            return await call();
        }
        catch (RequestFailedException failure) when (IsTransient(failure.Status))
        {
            throw new KeyCustodianUnavailableException(
                operation,
                $"Key Vault answered {failure.Status} while asked to {operation}.",
                retryAfter: null,
                failure);
        }
        catch (RequestFailedException failure)
        {
            throw new KeyCustodianFailedException(operation, failure);
        }
        catch (Exception failure) when (IsTransientTransport(failure, cancellationToken))
        {
            throw new KeyCustodianUnavailableException(
                operation,
                $"Key Vault could not be reached to {operation}.",
                retryAfter: null,
                failure);
        }
    }

    /// <summary>
    /// Whether a failure that never reached the vault may cure itself: a connection error, or the SDK's own
    /// timeout, which arrives as cancellation while the caller's token is not cancelled. A caller that did
    /// cancel gets its own outcome back, not a report of an outage.
    /// </summary>
    private static bool IsTransientTransport(Exception exception, CancellationToken cancellationToken)
        => exception switch
        {
            HttpRequestException => true,
            IOException => true,
            OperationCanceledException => !cancellationToken.IsCancellationRequested,
            _ => false,
        };
}
