// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.SecurityEvents.Events;

/// <summary>
/// What a deployment refuses to emit. An event vocabulary's base specification says what a payload MAY
/// carry; a profile a deployment claims can demand more of the same payload, and this is where that extra
/// demand is stated.
/// </summary>
/// <remarks>
/// It lives here, in the assembly every event vocabulary and every transmitter references, because the two
/// sides of the question are in packages that do not reference each other: the rule belongs to the
/// vocabulary that defines the payload, and the moment it must be asked belongs to the transmitter.
/// <para>
/// A policy speaks about the payload alone, so it is consulted ONCE per event rather than once per stream:
/// the payload is the same for every receiver, and a per-stream answer would emit to some and withhold
/// from others by iteration order.
/// </para>
/// <para>
/// Registering one is how a deployment CLAIMS a profile. Nothing is registered by default, so a
/// transmitter that claims nothing keeps emitting whatever its host builds.
/// </para>
/// </remarks>
public interface IEventPayloadPolicy
{
    /// <summary>
    /// Why this deployment will not emit the event, or null when it will.
    /// </summary>
    /// <param name="eventType">The event type URI the payload is carried under.</param>
    /// <param name="payload">The payload the application built; null for an event that carries none.</param>
    /// <returns>An operator-facing sentence naming what is missing, or null to let the event go.</returns>
    string? RefusalOf(string eventType, IEventPayload? payload);
}
