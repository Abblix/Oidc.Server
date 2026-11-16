// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents;

/// <summary>
/// The typed-payload and signing steps of a <see cref="SecurityEventTokenBuilder"/>, built on its public members.
/// </summary>
public static class SecurityEventTokenBuilderExtensions
{
    /// <summary>
    /// Adds an event statement whose payload is a typed model, serialized here so the caller
    /// works in terms of the profiling specification's type rather than raw JSON.
    /// </summary>
    /// <typeparam name="TPayload">The type modelling the event's payload.</typeparam>
    /// <param name="builder">The builder the statement is added to.</param>
    /// <param name="eventType">The event identifier URI.</param>
    /// <param name="payload">The payload value.</param>
    /// <param name="serializerOptions">
    /// Options for payload serialization; null takes the serializer's defaults. A receiver reads
    /// the payload back with the options its <see cref="EventTypeRegistry"/> holds, so a
    /// transmitter and receiver sharing a dictionary package agree by construction.</param>
    /// <returns>The same builder.</returns>
    /// <exception cref="ArgumentException">
    /// A statement with the same event identifier was already added, or the payload serialized
    /// into something other than a JSON object, which RFC 8417 Section 2.2 requires the value to
    /// be.</exception>
    /// <exception cref="InvalidOperationException">
    /// A second statement was added while <see cref="SecurityEventTokenBuilder.SingleEventStatement"/> is set.
    /// </exception>
    public static SecurityEventTokenBuilder WithEvent<TPayload>(
        this SecurityEventTokenBuilder builder,
        string eventType,
        TPayload payload,
        JsonSerializerOptions? serializerOptions = null)
        where TPayload : IEventPayload
    {
        ArgumentNullException.ThrowIfNull(payload);

        // A passthrough payload re-transmits what arrived, not a serialization of the wrapper:
        // the wrapper is this package's shape, while its Json is the event's.
        var node = payload is UnknownEventPayload unknown
            ? unknown.Json.DeepClone()
            : JsonSerializer.SerializeToNode(payload, payload.GetType(), serializerOptions);

        if (node is not JsonObject payloadObject)
        {
            throw new ArgumentException(
                $"The payload of event '{eventType}' serialized into {node?.GetValueKind().ToString() ?? "null"}, "
                + "but an event payload must be a JSON object (RFC 8417 Section 2.2).",
                nameof(payload));
        }

        return builder.WithEvent(eventType, payloadObject);
    }

    /// <summary>
    /// Materializes the SET and hands it to the signer, returning the compact serialization a
    /// transmitter delivers.
    /// </summary>
    /// <param name="builder">The builder the token is materialized from.</param>
    /// <param name="signer">The signer owning key and algorithm choice.</param>
    /// <param name="cancellationToken">Cancels the signing operation mid-flight.</param>
    public static Task<string> SignAsync(
        this SecurityEventTokenBuilder builder,
        ISecurityEventTokenSigner signer,
        CancellationToken cancellationToken = default)
    {
        ArgumentNullException.ThrowIfNull(signer);

        return signer.SignAsync(builder.Build(), cancellationToken);
    }
}
