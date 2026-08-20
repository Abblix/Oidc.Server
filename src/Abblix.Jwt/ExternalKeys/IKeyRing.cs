// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Hands out the keys it holds to whoever asks for them.
/// </summary>
/// <remarks>
/// The ring knows how keys are minted, sealed, shared and rotated, and nothing about what they are then used
/// for. An OpenID Provider asks it for the keys it signs with and publishes; a client asks it for the keys it
/// protects stored sessions with. Both get the same answer from the same ring, which is why this contract
/// names neither of them.
/// </remarks>
public interface IKeyRing
{
    /// <summary>
    /// Returns the keys for a role, the one to produce with leading.
    /// </summary>
    /// <param name="usage">Which role to serve, signature or encryption.</param>
    /// <param name="includePrivateKeys">
    /// Whether the caller needs the private half, which only signing and decryption do. Publication must not.
    /// </param>
    /// <remarks>
    /// The ordering carries meaning: whoever produces takes the first key for an algorithm, while every key
    /// stays in the result so consumers can still verify or decrypt across a rotation.
    /// </remarks>
    IEnumerable<JsonWebKey> Get(string usage, bool includePrivateKeys);

    /// <summary>
    /// Brings the ring up to date: mints what the current period lacks, retires what has expired, and reloads
    /// what other instances have minted.
    /// </summary>
    /// <param name="cancellationToken">Cancels the refresh.</param>
    Task RefreshAsync(CancellationToken cancellationToken);
}
