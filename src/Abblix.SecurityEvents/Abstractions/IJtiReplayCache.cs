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

namespace Abblix.SecurityEvents.Abstractions;

/// <summary>
/// Tracks which SETs have already been processed, by the use RFC 8417 Section 2.2 names for the
/// "jti" claim: "MAY be used by clients to track whether a particular SET has already been
/// received".
/// </summary>
/// <remarks>
/// <para>
/// Registration is deliberately OUTSIDE the validation pipeline. Validation answers a question
/// and is free of side effects; registering an identifier is a mutation, and a pipeline that
/// mutated on a token a later step rejects would need an undo. The consumer calls this after a
/// successful validation and before acting on the event.
/// </para>
/// <para>
/// A replay is not a protocol error: RFC 8935 Section 2 lets a transmitter deliver the same SET
/// again regardless of earlier responses, so event processing is idempotent by contract, and a
/// repeat is skipped and acknowledged rather than reported.
/// </para>
/// </remarks>
public interface IJtiReplayCache
{
    /// <summary>
    /// Registers a token identifier, telling a first delivery from a repeat.
    /// </summary>
    /// <param name="issuer">
    /// The token's issuer. The pair is the key, because "jti" is unique "within a particular
    /// event feed" (RFC 8417 Section 2.2) - two issuers may mint the same identifier and neither
    /// is replaying the other.</param>
    /// <param name="jwtId">The token's "jti" value.</param>
    /// <param name="issuedAt">
    /// The token's "iat", which is what bounds the cache's memory: the validation window rejects
    /// anything older, so entries beyond the window are safe to evict.</param>
    /// <param name="cancellationToken">Cancels I/O a distributed implementation performs.</param>
    /// <returns>True when the identifier is new and now registered; false when it was seen before.
    /// </returns>
    ValueTask<bool> TryRegisterAsync(
        string issuer,
        string jwtId,
        DateTimeOffset issuedAt,
        CancellationToken cancellationToken = default);
}
