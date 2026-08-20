// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Where the private half of a key lives once a custodian is wired. This is the security posture, so a host names
/// it at the call site and the library never picks one.
/// </summary>
/// <remarks>
/// Recorded rather than inferred from the registrations, so a host that layers its own key provider over the
/// placement's does not change the answer. An enum rather than the name of the call that chose it: consumers
/// dispatch on this, and a dispatch on a method name is a magic string that survives the method being renamed.
/// </remarks>
public enum KeyPlacement
{
    /// <summary>
    /// The private halves stay in the custodian. Every signature and every Content Encryption Key unwrap is a
    /// round-trip to it, and a compromised process holds no key to leak.
    /// </summary>
    Custodian,

    /// <summary>
    /// The keys are minted in this process, sealed to the custodian's key-encryption key and shared as ciphertext
    /// through an <see cref="IKeyRingStore"/>. Signing then runs locally, so the custodian is touched once per key
    /// rather than once per token.
    /// </summary>
    InProcess,
}
