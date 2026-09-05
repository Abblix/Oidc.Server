// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt;

/// <summary>
/// One version of a custodian-held key: its public half and when the custodian created that version. The
/// public key carries the version-specific <c>kid</c> that routes a private operation back to this exact
/// version, so publishing a key's versions lets a client verify a signature made by any of them and lets the
/// server unwrap a JWE encrypted to any of them. The creation time is what a rotation policy reads to hold a
/// freshly minted version as announced-but-not-yet-signing until client JWKS caches catch up (the propagation
/// window), and to keep a superseded version published until its tokens expire.
/// </summary>
/// <param name="PublicKey">The public-only key material for this version, with its version-specific <c>kid</c>.</param>
/// <param name="CreatedAt">When the custodian created this version. A custodian that does not track a creation
/// time reports <see cref="DateTimeOffset.MinValue"/>, which a rotation policy treats as "always past the
/// propagation window", so a single non-rotating key is always eligible to sign.</param>
public readonly record struct KeyVersion(JsonWebKey PublicKey, DateTimeOffset CreatedAt);
