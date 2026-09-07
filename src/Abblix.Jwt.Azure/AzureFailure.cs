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
/// Decides which of the library's two custodian failures an Azure answer is, so an endpoint can say whether
/// the caller should come back. Only this package can make that call: the endpoint sees an exception, and the
/// status that separates "the service is busy" from "this identity may not do that" is the service's alone.
/// Both Azure services this package talks to come through here - the vault that holds the keys, and the
/// storage account that holds the ring of sealed ones - because both answer with the same SDK failure.
/// </summary>
internal static class AzureFailure
{
    /// <summary>
    /// Whether a status is one that a later attempt may find cleared. A throttled service answers 429 and one
    /// having a bad time answers 5xx; a request timeout means the service gave up waiting for a request rather
    /// than reading one it disliked (RFC 9110 section 15.5.9). None of those is about the request. A 401 or 403
    /// is a grant that is missing, a 404 a key or an entry that is not there, and a 400 a request that was
    /// wrong - all of which meet the same answer next time.
    /// </summary>
    /// <param name="status">The status the service answered with, or zero when it never answered. Zero is not
    /// an HTTP status: it is what the SDK reports for an attempt that failed before any answer, and those
    /// attempts reach this method inside the aggregated retry failure. Driven by the row that unplugs the
    /// transport: without zero here, a vault that cannot be reached is read as permanent.</param>
    internal static bool IsTransient(int status)
        => status is 0
            or (int)HttpStatusCode.RequestTimeout
            or (int)HttpStatusCode.TooManyRequests
            or >= (int)HttpStatusCode.InternalServerError;

    /// <summary>
    /// Reports an Azure failure as one of the two, so it arrives at an endpoint that can read it.
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
                    $"Azure could not be asked to {operation}.",
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
