// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Events;

/// <summary>
/// Marks a type as the payload of an event statement (RFC 8417 Section 2: the "payload" is the
/// JSON object paired with an event identifier inside the "events" claim).
/// </summary>
/// <remarks>
/// The interface carries no members on purpose. A payload's shape belongs to the profiling
/// specification that defines the event (RFC 8417 Section 1.2), so the only thing all payloads
/// share is BEING one - and the marker is what lets <see cref="EventTypeRegistry"/> map event
/// identifier URIs to types without accepting arbitrary classes, the way a string-to-Type
/// dictionary alone would.
/// </remarks>
public interface IEventPayload;
