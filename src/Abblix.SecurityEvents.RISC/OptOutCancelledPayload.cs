// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.RISC;

/// <summary>
/// Opt Out Cancelled (RISC 1.0 Section 2.8.3): the account identified by the subject cancelled
/// a pending opt-out and is back in the opt-in state. The event carries no attributes.
/// </summary>
public sealed record OptOutCancelledPayload : IEventPayload;
