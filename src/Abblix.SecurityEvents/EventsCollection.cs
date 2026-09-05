// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections;
using System.Text.Json.Nodes;

namespace Abblix.SecurityEvents;

/// <summary>
/// The value of the "events" claim: the event statements a SET expresses, each a name/value pair
/// whose name is the event identifier URI and whose value is the event's payload
/// (RFC 8417 Section 2.2).
/// </summary>
/// <remarks>
/// The statements of one SET describe aspects of ONE state transition: RFC 8417 Section 2 says
/// multiple identifiers "represent multiple aspects of the same state transition" and Section 2.2
/// that the claim "MUST NOT be used to express multiple independent logical events". That rule is
/// about meaning, so no code can check it - it is the caller's to honour when adding a second
/// statement.
/// </remarks>
/// <param name="json">
/// The JSON object holding the event statements, read and written in place, never copied.</param>
public sealed class EventsCollection(JsonObject json) : IReadOnlyCollection<KeyValuePair<string, JsonObject>>
{
    /// <summary>
    /// Creates an empty collection, to be filled through <see cref="Add"/>.
    /// </summary>
    public EventsCollection()
        : this(new JsonObject())
    {
    }

    /// <summary>
    /// The underlying JSON object, in the exact shape the "events" claim carries on the wire.
    /// </summary>
    public JsonObject Json { get; } = json;

    /// <summary>
    /// The number of event statements. RFC 8417 Section 2 requires at least one in a valid SET;
    /// whether that holds for a token read off the wire is the validation pipeline's question.
    /// </summary>
    public int Count => Json.Count;

    /// <summary>
    /// Tells whether a statement with the given event identifier is present.
    /// </summary>
    /// <param name="eventType">The event identifier URI.</param>
    public bool Contains(string eventType) => Json.ContainsKey(eventType);

    /// <summary>
    /// Retrieves the payload of the statement with the given event identifier.
    /// </summary>
    /// <param name="eventType">The event identifier URI.</param>
    /// <param name="payload">The event's payload object when present and well-formed.</param>
    /// <returns>
    /// True when the statement exists and its value is a JSON object, as RFC 8417 Section 2.2
    /// requires; false when it is absent or malformed.</returns>
    public bool TryGetPayload(string eventType, out JsonObject payload)
    {
        if (Json.TryGetPropertyValue(eventType, out var node) && node is JsonObject value)
        {
            payload = value;
            return true;
        }

        payload = null!;
        return false;
    }

    /// <summary>
    /// Adds an event statement.
    /// </summary>
    /// <param name="eventType">
    /// The event identifier URI. RFC 8417 Section 2.2 asks for stable values, such as a permanent
    /// URL of the event's specification.</param>
    /// <param name="payload">
    /// The event's payload. The parameter type already keeps Section 2.2's "the corresponding
    /// value MUST be a JSON object". Null stands for an event with no payload claims, which
    /// "SHALL be represented as the empty JSON object" (RFC 8417 Section 2) - the empty object is
    /// written here so no caller has to remember that rule.</param>
    /// <exception cref="ArgumentException">
    /// A statement with the same event identifier is already present - "Multiple event identifiers
    /// with the same value MUST NOT be used" (RFC 8417 Section 2.2) - or the payload is still
    /// attached to another JSON tree; pass a copy of a parsed node rather than the node itself.
    /// </exception>
    public void Add(string eventType, JsonObject? payload = null)
    {
        ArgumentException.ThrowIfNullOrEmpty(eventType);

        if (Json.ContainsKey(eventType))
        {
            throw new ArgumentException(
                $"An event statement '{eventType}' is already present: multiple event identifiers with "
                + "the same value must not be used (RFC 8417 Section 2.2).",
                nameof(eventType));
        }

        // Without this check the serializer throws its own "node already has a parent", which
        // names neither the event nor the way out.
        if (payload is { Parent: not null })
        {
            throw new ArgumentException(
                $"The payload for '{eventType}' is attached to another JSON tree - typically a "
                + "previously parsed token. Pass a copy (payload.DeepClone()) instead of moving a node "
                + "out of its owner.",
                nameof(payload));
        }

        Json.Add(eventType, payload ?? new JsonObject());
    }

    /// <summary>
    /// Enumerates the event statements as (event identifier, payload) pairs.
    /// </summary>
    /// <exception cref="InvalidOperationException">
    /// A statement's value is not a JSON object. RFC 8417 Section 2.2 forbids that shape, and this
    /// view refuses to invent a payload for it; the validation pipeline is where such a token gets
    /// its verdict.</exception>
    public IEnumerator<KeyValuePair<string, JsonObject>> GetEnumerator()
    {
        foreach (var (eventType, payload) in Json)
        {
            if (payload is not JsonObject payloadObject)
            {
                throw new InvalidOperationException(
                    $"The event statement '{eventType}' carries a payload that is not a JSON object, "
                    + "which RFC 8417 Section 2.2 forbids.");
            }

            yield return new KeyValuePair<string, JsonObject>(eventType, payloadObject);
        }
    }

    IEnumerator IEnumerable.GetEnumerator() => GetEnumerator();
}
