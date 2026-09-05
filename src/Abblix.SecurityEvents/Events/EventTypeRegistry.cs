// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Nodes;

namespace Abblix.SecurityEvents.Events;

/// <summary>
/// Maps event identifier URIs to the payload types that model them, and deserializes payloads
/// through that map.
/// </summary>
/// <remarks>
/// The registry is filled during configuration and read at validation time; registration is not
/// synchronized, so it belongs at startup, which is where the DI extension calls it. An event
/// dictionary package - the CAEP one, for instance - is nothing but a set of registrations over
/// this mechanism.
/// </remarks>
/// <param name="serializerOptions">
/// Options for payload deserialization; null takes the serializer's defaults. Property-name
/// matching stays exact either way - wire names on payload types belong in
/// JsonPropertyName attributes, where the profiling specification's spelling is
/// visible next to the member it names.</param>
public sealed class EventTypeRegistry(JsonSerializerOptions? serializerOptions = null)
{
    private readonly Dictionary<string, Type> _payloadTypes = new(StringComparer.Ordinal);

    /// <summary>
    /// The serializer options payloads are read with. Owned by the registry so every payload in a
    /// process is read by the same rules, whichever step or consumer asks.
    /// </summary>
    private readonly JsonSerializerOptions _serializerOptions = serializerOptions ?? JsonSerializerOptions.Default;

    /// <summary>
    /// Registers a payload type for an event identifier.
    /// </summary>
    /// <typeparam name="TPayload">The type modelling the event's payload.</typeparam>
    /// <param name="eventType">
    /// The event identifier URI, exactly as transmitters spell it - RFC 8417 Section 2.2 asks for
    /// stable values, and the comparison here is an exact string match.</param>
    /// <exception cref="ArgumentException">
    /// The event identifier is already registered. Two types for one URI would make the answer to
    /// "what does this event deserialize into" depend on registration order, which is the kind of
    /// fact nobody can read off the code.</exception>
    public void Register<TPayload>(string eventType)
        where TPayload : IEventPayload
    {
        ArgumentException.ThrowIfNullOrEmpty(eventType);

        if (!_payloadTypes.TryAdd(eventType, typeof(TPayload)))
        {
            throw new ArgumentException(
                $"The event type '{eventType}' is already registered to '{_payloadTypes[eventType]}'.",
                nameof(eventType));
        }
    }

    /// <summary>
    /// Retrieves the payload type registered for an event identifier.
    /// </summary>
    /// <param name="eventType">The event identifier URI.</param>
    /// <param name="payloadType">The registered type, when there is one.</param>
    public bool TryGetPayloadType(string eventType, out Type payloadType)
    {
        if (_payloadTypes.TryGetValue(eventType, out var registered))
        {
            payloadType = registered;
            return true;
        }

        payloadType = null!;
        return false;
    }

    /// <summary>
    /// Deserializes an event's payload: into its registered type when the event identifier is
    /// known, into <see cref="UnknownEventPayload"/> when it is not.
    /// </summary>
    /// <param name="eventType">The event identifier URI.</param>
    /// <param name="payload">The payload object from the "events" claim.</param>
    /// <returns>The typed payload, never null.</returns>
    /// <exception cref="JsonException">
    /// The payload does not deserialize into the registered type. A malformed payload of a KNOWN
    /// type is a real error - the transmitter and receiver disagree about a shape both claim to
    /// know - unlike an unknown type, which is the forward-compatibility case the passthrough
    /// exists for.</exception>
    public IEventPayload Deserialize(string eventType, JsonObject payload)
    {
        ArgumentException.ThrowIfNullOrEmpty(eventType);
        ArgumentNullException.ThrowIfNull(payload);

        if (!_payloadTypes.TryGetValue(eventType, out var payloadType))
        {
            return new UnknownEventPayload(payload);
        }

        var deserialized = payload.Deserialize(payloadType, _serializerOptions)
            ?? throw new JsonException(
                $"The payload of event '{eventType}' deserialized to null instead of a '{payloadType}'.");

        return (IEventPayload)deserialized;
    }
}
