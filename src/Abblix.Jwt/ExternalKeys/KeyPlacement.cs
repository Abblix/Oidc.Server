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
