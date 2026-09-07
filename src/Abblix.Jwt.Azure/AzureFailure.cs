// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// meet the same answer next time. A request timeout is temporary as well.
    /// </summary>
    /// <param name="status">The status the service answered with, or zero when it never answered: the SDK
    /// reports a request that did not reach the service with no status at all, and that says nothing about the
    /// request either.</param>
    internal static bool IsTransient(int status)
        => status is 0
            or (int)HttpStatusCode.RequestTimeout
            or (int)HttpStatusCode.TooManyRequests
            or >= (int)HttpStatusCode.InternalServerError;

    /// <summary>
    /// Reports a Key Vault failure as one of the two, so it arrives at an endpoint that can read it.
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
        catch (Exception failure) when (IsCustodianFailure(failure, cancellationToken))
        {
            throw IsTemporary(failure, cancellationToken)
                ? new KeyCustodianUnavailableException(
                    operation,
                    $"Key Vault could not be asked to {operation}.",
                    retryAfter: null,
                    failure)
                : new KeyCustodianFailedException(operation, failure);
        }
    }

    /// <summary>
    /// Whether this exception is the vault answering, or failing to. Anything else - an algorithm this package
    /// does not map, a defect of our own - keeps travelling untouched, because reshaping it would hide a fault
    /// that is not the custodian's behind a status that says it is.
    /// </summary>
    /// <remarks>
    /// The SDK retries a failed request itself and, when every attempt fails, reports them together. Both
    /// questions therefore read through that wrapper: without it a vault that could not be reached arrives as a
    /// shape nothing recognizes and escapes unclassified, which is the failure this seam exists to prevent.
    /// </remarks>
    private static bool IsCustodianFailure(Exception exception, CancellationToken cancellationToken)
        => exception switch
        {
            AggregateException aggregate =>
                aggregate.InnerExceptions.Any(inner => IsCustodianFailure(inner, cancellationToken)),

            RequestFailedException => true,
            HttpRequestException => true,
            IOException => true,

            // A caller that cancelled gets its own outcome back, never a report of an outage.
            OperationCanceledException => !cancellationToken.IsCancellationRequested,

            _ => false,
        };

    /// <summary>
    /// Whether waiting may cure it. An aggregated failure is temporary when any attempt inside it was: the SDK
    /// keeps retrying past a transient answer, so the last attempt is not the whole story.
    /// </summary>
    private static bool IsTemporary(Exception exception, CancellationToken cancellationToken)
        => exception switch
        {
            AggregateException aggregate =>
                aggregate.InnerExceptions.Any(inner => IsTemporary(inner, cancellationToken)),

            RequestFailedException failure => IsTransient(failure.Status),
            HttpRequestException => true,
            IOException => true,
            OperationCanceledException => !cancellationToken.IsCancellationRequested,

            _ => false,
        };
}
