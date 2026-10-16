// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Serialization;

namespace Abblix.SharedSignals.Transmitter;

/// <summary>
/// One SET waiting in a stream's outbox: minted and addressed, signed only when it is delivered.
/// </summary>
/// <param name="JwtId">
/// The token's "jti", the identifier acknowledgements and error reports use
/// (RFC 8936 Section 2.2).</param>
/// <param name="Token">The token as it waits: unsigned, in the form <see cref="QueuedEventSigner"/> keeps it and
/// signs it from at every delivery. An item a version that signed on enqueue left in a durable outbox holds that
/// compact token instead, which is delivered as it is.</param>
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
    [property: JsonPropertyName("token")] string Token,
    [property: JsonPropertyName("is_status_announcement")] bool IsStatusAnnouncement = false);
