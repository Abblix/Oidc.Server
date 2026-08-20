// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.SecurityEvents.Events;

namespace Abblix.SecurityEvents.Validation;

/// <summary>
/// What a successful validation run hands to the consumer: the token, now carrying its issuer's
/// authority, and the event payloads already deserialized so the consumer does not repeat work
/// the pipeline has done.
/// </summary>
/// <param name="Token">The validated SET.</param>
/// <param name="EventPayloads">
/// The typed event payloads keyed by event identifier - each the registered model or the raw
/// passthrough - or null when the pipeline was composed without the payload deserialization
/// step, in which case the raw statements remain available through the token's events.</param>
public record ValidatedSecurityEventToken(
    SecurityEventToken Token,
    IReadOnlyDictionary<string, IEventPayload>? EventPayloads);
