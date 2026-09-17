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
    /// When the newest key serving a role appeared, or null while the ring holds none for it.
    /// </summary>
    /// <param name="usage">Which role to report on, signature or encryption.</param>
    /// <remarks>
    /// A ring whose rotation has stopped looks exactly like one that is working: it keeps serving the keys it
    /// already holds, every signature still verifies, and nothing goes red - while it drifts away from what the
    /// other instances hold. The age of the newest key is what tells the two apart, and it tells them apart only
    /// for a role this ring actually rotates. A role served by a key the host adopted, or by one that names no
    /// role and therefore serves every role, has no rotation to be late for: its answer stands still by design,
    /// and read as a schedule it says "stopped" forever.
    /// <para>
    /// Answered from what the ring holds rather than from the store behind it, so a custodian that goes briefly
    /// unreachable does not turn into an unhealthy instance - which is the coupling the refresh loop avoids by
    /// logging and carrying on. A ring that has never loaded holds nothing and answers null, which is the same
    /// answer as a role it has no key for: null says the ring cannot speak about this role, never that the role
    /// is healthy or that it is not.
    /// </para>
    /// <para>
    /// A ring that rotates only when asked for a key - the in-box one that mints in this process does - answers
    /// about what it has been asked for. Reading it as a schedule needs a ring something keeps current.
    /// </para>
    /// </remarks>
    DateTimeOffset? NewestKeyCreatedAt(string usage);

    /// <summary>
    /// Brings the ring up to date: mints what the current period lacks, retires what has expired, and reloads
    /// what other instances have minted.
    /// </summary>
    /// <param name="cancellationToken">Cancels the refresh.</param>
    Task RefreshAsync(CancellationToken cancellationToken);
}
