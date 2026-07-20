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

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// One entry of the key ring: a private key the server minted, encrypted to the custodian's key-encryption key,
/// plus the two facts needed to place it without opening it.
/// </summary>
/// <remarks>
/// The entry is self-contained on purpose. Every pod derives the same state from the same set of entries with no
/// coordination, and the only operation that ever needs synchronising is creating one, so an entry is written
/// once and never updated. That is what keeps <see cref="IKeyRingStore"/> to an insert-if-absent and no CAS on
/// update.
/// </remarks>
public sealed record StoredKey
{
    /// <summary>
    /// The entry's identity, and the token every pod races for: it is derived deterministically from the key's
    /// role, its algorithm and the rotation period, so all pods compute the same value and exactly one insert
    /// wins.
    /// </summary>
    public required string Id { get; init; }

    /// <summary>
    /// The envelope: the private JWK's JSON, encrypted to the KEK, in JWE compact serialization. Its header names
    /// the KEK version that unwraps it (<c>kid</c>) and the algorithms used (<c>alg</c>, <c>enc</c>), so the entry
    /// repeats none of that.
    /// </summary>
    public required string Jwe { get; init; }

    /// <summary>
    /// When the key was minted, which decides when it starts signing: the active key is the newest one past
    /// <c>KeyRingOptions.KeyRolloverPropagation</c>.
    /// </summary>
    /// <remarks>
    /// Stored rather than derived from <see cref="Id"/>, though the period in the id implies it. The id is a
    /// coordinate on the rotation grid; this is the fact. Deriving it would let a change to the rotation interval
    /// silently reinterpret when existing keys were created.
    /// </remarks>
    public required DateTimeOffset CreatedAt { get; init; }
}
