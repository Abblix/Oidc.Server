// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.RISC;

/// <summary>
/// Recovery Information Changed (RISC 1.0 Section 2.10): the account identified by the subject
/// changed some of its recovery information - a recovery email added or removed, or an
/// identifier change at a provider NOT authoritative over the identifier, which Section 2.5
/// routes here instead of Identifier Changed. The event carries no attributes.
/// </summary>
public sealed record RecoveryInformationChangedPayload : IEventPayload;
