// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.RISC;

/// <summary>
/// Sessions Revoked (RISC 1.0 Section 2.11): all sessions of the account identified by the
/// subject have been revoked. The event carries no attributes.
/// </summary>
/// <remarks>
/// The specification deprecates this event type: new implementations MUST transmit the CAEP
/// session-revoked event instead. The type exists here so a RECEIVER still understands
/// transmitters that predate the deprecation - it is deliberately not marked obsolete, because
/// registering it for reception is exactly the supported use.
/// </remarks>
public sealed record SessionsRevokedPayload : IEventPayload;
