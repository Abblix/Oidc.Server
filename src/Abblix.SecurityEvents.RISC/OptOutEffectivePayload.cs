// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.RISC;

/// <summary>
/// Opt Out Effective (RISC 1.0 Section 2.8.4): the opt-out took effect and the account
/// identified by the subject no longer participates in RISC event exchanges - the last event
/// the receiver will see for it. The event carries no attributes.
/// </summary>
public sealed record OptOutEffectivePayload : IEventPayload;
