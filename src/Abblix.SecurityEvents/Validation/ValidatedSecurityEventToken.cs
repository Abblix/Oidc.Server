// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

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
