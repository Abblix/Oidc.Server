// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.RISC;

/// <summary>
/// Recovery Activated (RISC 1.0 Section 2.9): the account identified by the subject activated a
/// recovery flow - a moment attackers favour, which is why it is worth signalling. The event
/// carries no attributes.
/// </summary>
public sealed record RecoveryActivatedPayload : IEventPayload;
