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

using System.Text.Json.Serialization;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// One SET waiting in a stream's outbox: minted, signed, addressed - everything but delivered.
/// </summary>
/// <param name="JwtId">
/// The token's "jti", the identifier acknowledgements and error reports use
/// (RFC 8936 Section 2.2).</param>
/// <param name="CompactToken">The signed token in compact serialization, exactly as it will
/// travel.</param>
/// <param name="IsStatusAnnouncement">
/// True for the stream-updated event that escorts a transmitter-initiated status change: the
/// one item delivery must carry even over a stream that is paused or disabled, because
/// SSF 1.0 Section 8.1.5 wants it sent "before stopping the stream" - and the stop has, by the
/// time delivery runs, already happened.</param>
/// <remarks>
/// The JSON member names are pinned rather than left to the property names, because a durable
/// <see cref="IEventOutbox"/> persists this type and the two ends of that store are two code versions
/// across a rolling deploy. Without them a rename - or a serializer configured with a naming policy -
/// reads every stored item back with null members instead of failing, and a null identifier is the one
/// shape that can be served and never acknowledged.
/// </remarks>
public sealed record OutboxItem(
    [property: JsonPropertyName("jti")] string JwtId,
    [property: JsonPropertyName("token")] string CompactToken,
    [property: JsonPropertyName("is_status_announcement")] bool IsStatusAnnouncement = false);
