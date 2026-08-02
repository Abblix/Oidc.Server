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

namespace Abblix.SecurityEvents.Events;

/// <summary>
/// Marks a type as the payload of an event statement (RFC 8417 Section 2: the "payload" is the
/// JSON object paired with an event identifier inside the "events" claim).
/// </summary>
/// <remarks>
/// The interface carries no members on purpose. A payload's shape belongs to the profiling
/// specification that defines the event (RFC 8417 Section 1.2), so the only thing all payloads
/// share is BEING one - and the marker is what lets <see cref="EventTypeRegistry"/> map event
/// identifier URIs to types without accepting arbitrary classes, the way a string-to-Type
/// dictionary alone would.
/// </remarks>
public interface IEventPayload;
