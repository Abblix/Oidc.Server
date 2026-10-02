// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SecurityEvents.Delivery;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.SharedSignals.MinimalApi;

/// <summary>
/// The route handlers of the management surface (Adapter): each translates a request into a call on
/// the host-agnostic service and its result back into a response, and nothing else.
/// </summary>
internal static class StreamManagementHandlers
{
    internal static async Task<IResult> CreateStreamAsync(
        HttpContext http,
        StreamManagementService service,
        CreateStreamRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.CreateStreamAsync(receiverId, request, cancellationToken))
            : BearerChallenges.Unauthenticated(http);

    /// <summary>
    /// One route, two reads: with "stream_id" the single configuration, without it the list -
    /// where an empty list is a receiver with no streams, never an error
    /// (SSF 1.0 Section 8.1.1.2).
    /// </summary>
    internal static async Task<IResult> GetStreamsAsync(
        HttpContext http,
        StreamManagementService service,
        [FromQuery(Name = StreamMemberNames.StreamId)] string? streamId,
        CancellationToken cancellationToken)
    {
        if (ReceiverIdOf(http) is not { } receiverId)
        {
            return BearerChallenges.Unauthenticated(http);
        }

        // Same reading of "named" as the two refusal routes below, so the three do not disagree
        // about one word. Here an unnamed stream is an ANSWER rather than an error, so
        // "?stream_id=" lists every stream instead of looking one up under the empty name and
        // reporting it missing.
        return string.IsNullOrEmpty(streamId)
            ? Render(await service.ListStreamsAsync(receiverId, cancellationToken))
            : Render(await service.GetStreamAsync(receiverId, streamId, cancellationToken));
    }

    internal static async Task<IResult> UpdateStreamAsync(
        HttpContext http,
        StreamManagementService service,
        UpdateStreamRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.UpdateStreamAsync(receiverId, request, cancellationToken))
            : BearerChallenges.Unauthenticated(http);

    internal static async Task<IResult> ReplaceStreamAsync(
        HttpContext http,
        StreamManagementService service,
        UpdateStreamRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.ReplaceStreamAsync(receiverId, request, cancellationToken))
            : BearerChallenges.Unauthenticated(http);

    internal static async Task<IResult> DeleteStreamAsync(
        HttpContext http,
        StreamManagementService service,
        [FromQuery(Name = StreamMemberNames.StreamId)] string? streamId,
        CancellationToken cancellationToken)
    {
        if (ReceiverIdOf(http) is not { } receiverId)
        {
            return BearerChallenges.Unauthenticated(http);
        }

        // "The DELETE request MUST include the 'stream_id'" per SSF 1.0 Section 8.1.1.5 -
        // without it there is nothing to delete. The condition asks whether a stream was
        // NAMED, not whether the parameter was absent: "?stream_id=" is present and names
        // nothing, and RFC 6750 Section 3.1 puts an unusable value in the same
        // invalid_request bucket as a missing one.
        return string.IsNullOrEmpty(streamId)
            ? BearerChallenges.MissingRequiredParameter(http, StreamMemberNames.StreamId)
            : Render(await service.DeleteStreamAsync(receiverId, streamId, cancellationToken));
    }

    internal static async Task<IResult> GetStatusAsync(
        HttpContext http,
        StreamManagementService service,
        [FromQuery(Name = StreamMemberNames.StreamId)] string? streamId,
        CancellationToken cancellationToken)
    {
        if (ReceiverIdOf(http) is not { } receiverId)
        {
            return BearerChallenges.Unauthenticated(http);
        }

        // The status read has no list fallback: "stream_id" is its REQUIRED parameter
        // (SSF 1.0 Section 8.1.2.1). Named rather than merely present, for the reason the
        // delete route states.
        return string.IsNullOrEmpty(streamId)
            ? BearerChallenges.MissingRequiredParameter(http, StreamMemberNames.StreamId)
            : Render(await service.GetStreamStatusAsync(receiverId, streamId, cancellationToken));
    }

    internal static async Task<IResult> UpdateStatusAsync(
        HttpContext http,
        StreamManagementService service,
        StreamStatus request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.UpdateStreamStatusAsync(receiverId, request, cancellationToken))
            : BearerChallenges.Unauthenticated(http);

    internal static async Task<IResult> AddSubjectAsync(
        HttpContext http,
        StreamManagementService service,
        AddSubjectRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.AddSubjectAsync(receiverId, request, cancellationToken))
            : BearerChallenges.Unauthenticated(http);

    internal static async Task<IResult> RemoveSubjectAsync(
        HttpContext http,
        StreamManagementService service,
        RemoveSubjectRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.RemoveSubjectAsync(receiverId, request, cancellationToken))
            : BearerChallenges.Unauthenticated(http);

    internal static async Task<IResult> RequestVerificationAsync(
        HttpContext http,
        StreamManagementService service,
        VerificationRequest request,
        CancellationToken cancellationToken)
        => ReceiverIdOf(http) is { } receiverId
            ? Render(await service.RequestVerificationAsync(receiverId, request, cancellationToken))
            : BearerChallenges.Unauthenticated(http);

    internal static async Task<IResult> PollAsync(
        HttpContext http,
        IStreamStore store,
        PollEndpointHandler handler,
        string streamId,
        PollRequest request,
        CancellationToken cancellationToken)
    {
        if (ReceiverIdOf(http) is not { } receiverId)
        {
            return BearerChallenges.Unauthenticated(http);
        }

        return await store.FindAsync(receiverId, streamId, cancellationToken) is { } stream
            ? Results.Json(await handler.HandleAsync(stream, request, cancellationToken))
            : Results.NotFound();
    }

    private static string? ReceiverIdOf(HttpContext context)
        => (context.RequestServices.GetService<SharedSignalsEndpointOptions>()
                ?? SharedSignalsEndpointRouteBuilderExtensions.DefaultEndpointOptions)
            .ReceiverIdSelector(context);

    internal static IResult Render<TBody>(ManagementResult<TBody> result)
        => result.Body is { } body
            ? Results.Json(body, statusCode: (int)result.StatusCode)
            : Results.StatusCode((int)result.StatusCode);
}
