// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt;

namespace Abblix.SecurityEvents.Abstractions;

/// <summary>
/// Answers which keys an issuer's signatures may verify against - the trust decision the
/// signature check delegates, since WHO holds an issuer's keys is deployment knowledge no
/// library can carry.
/// </summary>
/// <remarks>
/// An issuer this resolver yields no keys for is an issuer whose tokens cannot be accepted, and
/// the verifier reports that as a key miss rather than a bad signature: after a key rollover a
/// refetch may heal a miss, which a wrong signature never becomes.
/// </remarks>
public interface IIssuerKeyResolver
{
    /// <summary>
    /// Resolves the signature verification keys of an issuer.
    /// </summary>
    /// <param name="issuer">The issuer as its tokens spell it in "iss".</param>
    /// <param name="keyId">
    /// The "kid" the token's header names, when it names one. This is the key-rollover signal: a
    /// caching implementation that holds keys for the issuer but none under this identifier knows
    /// its copy predates a rotation and refreshes before answering, instead of failing a token
    /// signed with a key newer than the cache.</param>
    /// <param name="cancellationToken">Cancels retrieval mid-flight.</param>
    /// <returns>The issuer's current verification keys; empty when the issuer is not trusted.</returns>
    IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
        string issuer,
        string? keyId = null,
        CancellationToken cancellationToken = default);
}
