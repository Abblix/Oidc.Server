// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.RISC;

/// <summary>
/// Identifier Recycled (RISC 1.0 Section 2.6): the identifier in the subject was recycled and
/// now belongs to a DIFFERENT user - the receiver must stop treating it as the old account's.
/// The subject MUST be an email or phone_number subject. The event carries no attributes.
/// </summary>
public sealed record IdentifierRecycledPayload : IEventPayload;
