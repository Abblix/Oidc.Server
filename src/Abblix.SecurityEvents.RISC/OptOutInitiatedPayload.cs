// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.RISC;

/// <summary>
/// Opt Out Initiated (RISC 1.0 Section 2.8.2): the account identified by the subject asked to
/// leave RISC event exchanges, but events still flow for a period - the delay exists so a
/// hijacker cannot silence the alarm by opting the victim out immediately. The event carries no
/// attributes.
/// </summary>
public sealed record OptOutInitiatedPayload : IEventPayload;
