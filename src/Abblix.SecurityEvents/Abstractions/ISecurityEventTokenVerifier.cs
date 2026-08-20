// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt;
using Abblix.SecurityEvents.Validation;
using Abblix.Utils;

namespace Abblix.SecurityEvents.Abstractions;

/// <summary>
/// Verifies a SET's signature and yields the token whose claims are thereby the issuer's words:
/// the bridge between the validation pipeline and whatever cryptography the host runs.
/// </summary>
/// <remarks>
/// The verifier owns key resolution and the algorithm allowlist, and it reports failures already
/// in this package's error vocabulary, because only the implementation can tell a signature that
/// does not verify from a key that was not found - the distinction a receiver acts on, since a
/// key miss may heal after refetching the issuer's keys and a bad signature never does. Every
/// check beyond the signature - typing, audience, freshness - belongs to the pipeline's steps,
/// where a profile can see and compose it.
/// </remarks>
public interface ISecurityEventTokenVerifier
{
    /// <summary>
    /// Verifies the token's signature.
    /// </summary>
    /// <param name="compactToken">The token as received, in compact serialization.</param>
    /// <param name="keyId">
    /// The "kid" the token's header names, when the caller has already parsed it - the signature
    /// step has - so a caching key resolver can recognise a rollover without re-parsing the
    /// token.</param>
    /// <param name="cancellationToken">Cancels key retrieval mid-flight.</param>
    /// <returns>
    /// The parsed token on success - claims now carrying the issuer's authority - or the error a
    /// receiver branches on.</returns>
    Task<Result<JsonWebToken, SecurityEventTokenValidationError>> VerifyAsync(
        string compactToken,
        string? keyId = null,
        CancellationToken cancellationToken = default);
}
