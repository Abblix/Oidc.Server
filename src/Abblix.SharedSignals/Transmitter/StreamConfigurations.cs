// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// Builds a stream's configuration (Factory): the transmitter supplies identity, audience and the
/// delivered-events intersection, the receiver's proposal supplies the rest (SSF 1.0 Section 8.1.1).
/// </summary>
internal static class StreamConfigurations
{
    /// <summary>
    /// The identifier of a stream the management API creates: a GUID, so it is unique across receivers
    /// and carried unchanged into a poll address.
    /// </summary>
    public static string NewStreamId() => Guid.NewGuid().ToString("N");

    /// <summary>
    /// The configuration of a stream being created (SSF 1.0 Section 8.1.1.1).
    /// </summary>
    /// <param name="options">The deployment's one-time decisions.</param>
    /// <param name="receiverId">The authenticated receiver identity.</param>
    /// <param name="streamId">The identifier the new stream gets.</param>
    /// <param name="request">The receiver-supplied half of the configuration.</param>
    /// <param name="delivery">The delivery already accepted for the stream.</param>
    public static StreamConfiguration New(
        SharedSignalsTransmitterOptions options,
        string receiverId,
        string streamId,
        CreateStreamRequest request,
        StreamDeliveryMethod delivery)
        => new()
        {
            StreamId = streamId,
            Issuer = options.Issuer,
            Audiences = [.. options.AudiencesFactory?.Invoke(receiverId) ?? [receiverId]],
            EventsSupported = options.EventsSupported is { Count: > 0 } supported ? supported : null,
            EventsRequested = request.EventsRequested,
            EventsDelivered = DeliveredOf(options, request.EventsRequested),
            Delivery = delivery,
            MinVerificationInterval = options.MinVerificationInterval,
            Description = request.Description,
        };

    /// <summary>
    /// "events_delivered" as SSF 1.0 Section 8.1.1 defines it: a subset of the intersection of
    /// supported and requested, kept in the receiver's request order.
    /// </summary>
    /// <param name="options">Carries the events this transmitter supports.</param>
    /// <param name="requested">The events the receiver asked for, if it named any.</param>
    public static IReadOnlyList<string> DeliveredOf(
        SharedSignalsTransmitterOptions options,
        IReadOnlyList<string>? requested)
        => requested is null
            ? []
            : [.. requested.Where(eventType => options.EventsSupported.Contains(eventType, StringComparer.Ordinal))];
}
