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

namespace Abblix.Jwt.ReplayPrevention;

/// <summary>
/// Remembers the identifiers of single-use tokens so a second presentation of the same one can
/// be told from the first. Every JWT profile that forbids replay needs this and needs it in the
/// same shape - a DPoP proof (RFC 9449 Section 11.1), a client assertion (RFC 7523 Section 5.2)
/// and a Security Event Token (RFC 8417 Section 2.2) differ in what they call the identifier and
/// how long it stays interesting, never in the question they ask of the cache.
/// </summary>
/// <remarks>
/// The contract is reserve-and-check in one call, so a caller cannot read, decide and write in
/// three steps that another caller slips between. Whether the reservation is strictly atomic is
/// the implementation's promise, not this interface's: the shipped
/// <see cref="DistributedReplayCache"/> rides <c>IDistributedCache</c>, which exposes only Get
/// and Set, so its answer is probabilistic within one cache round trip. A deployment that needs
/// strict single-use takes a backend-native primitive behind this same interface, which is what
/// <see cref="ConditionalWriteReplayCache"/> is for: it holds everything around the primitive and
/// takes the primitive itself from the deployment - Redis <c>SET NX PX</c>, SQL
/// <c>INSERT ... ON CONFLICT DO NOTHING</c>, and their equivalents.
/// </remarks>
public interface IReplayCache
{
    /// <summary>
    /// Reserves an identifier, answering whether this is its first sighting.
    /// </summary>
    /// <param name="identifier">
    /// What identifies the token. A profile whose identifier is unique only within a scope
    /// composes that scope into the value it passes - a SET's "jti" is unique per event feed
    /// (RFC 8417 Section 2.2), so its receiver reserves the issuer and the identifier together.
    /// </param>
    /// <param name="expiresAt">
    /// When the identifier stops being worth remembering, which is the last moment a replay of
    /// this token could still pass the caller's own freshness checks. Forgetting earlier would
    /// let that token replay; the implementation is free to remember longer.</param>
    /// <param name="cancellationToken">Cancels the cache round trip.</param>
    /// <returns>
    /// True when the identifier was newly reserved and the token is therefore fresh; false when
    /// it was already there, which is a replay.</returns>
    Task<bool> TryReserveAsync(
        string identifier,
        DateTimeOffset expiresAt,
        CancellationToken cancellationToken = default);
}
