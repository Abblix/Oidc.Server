// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
