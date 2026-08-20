// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;

namespace Abblix.SecurityEvents.Events;

/// <summary>
/// The payload of an event whose type is not registered, carried as raw JSON.
/// </summary>
/// <remarks>
/// An unregistered type is a normal condition, not an error: a transmitter may start emitting a
/// new event type before its receivers update, and a receiver that rejected what it does not
/// recognise would go deaf exactly when the stream evolves. The raw payload stays available, so a
/// consumer can log it, route it, or ignore it deliberately - each of which requires having
/// received it.
/// </remarks>
/// <param name="json">The payload exactly as the event statement carried it.</param>
public sealed class UnknownEventPayload(JsonObject json) : IEventPayload
{
    /// <summary>
    /// The payload exactly as the event statement carried it.
    /// </summary>
    public JsonObject Json { get; } = json;
}
