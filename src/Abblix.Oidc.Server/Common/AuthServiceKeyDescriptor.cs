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

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// The lifecycle state of a service key as it moves through generation, activation, retirement and
/// deletion. The transitions themselves are driven by the rotation engine; this contract only names the
/// states so a persistent store and the read seam agree on their meaning.
/// </summary>
public enum KeyLifecycleStatus
{
    /// <summary>
    /// Generated and published for verification, but not yet used for signing. Publishing a key before it
    /// signs (publish-before-sign) gives relying parties time to fetch it, so the first token it signs
    /// already verifies against a key they hold.
    /// </summary>
    Pending,

    /// <summary>The current signing key: within its <c>not_before</c> / <c>not_after</c> window.</summary>
    Active,

    /// <summary>
    /// Past <c>not_after</c>, so it no longer signs, but still published so tokens it already signed keep
    /// verifying until they expire.
    /// </summary>
    Retiring,

    /// <summary>Past <c>delete_after</c>: no live token can reference it, so it is removed from publication.</summary>
    Retired,
}

/// <summary>
/// A service key together with the lifecycle metadata that lives AROUND it, never on it - the
/// <see cref="JsonWebKey"/> stays a pure JOSE / RFC 7517 model. This is the unit a persistent store saves
/// at generation and the read seam gates by time; the durable backend and the rotation that advances
/// <see cref="Status"/> ship separately.
/// </summary>
/// <param name="Key">The key itself. Its <c>use</c> is the standard JOSE member on the key; secret material
/// is present for a local key and absent for an external one (whose private half lives with a custodian).</param>
/// <param name="Status">The lifecycle state; see <see cref="KeyLifecycleStatus"/>.</param>
/// <param name="NotBefore">When the key becomes eligible to sign.</param>
/// <param name="NotAfter">When the key stops signing. After this the key still verifies published tokens
/// until <see cref="DeleteAfter"/>.</param>
/// <param name="DeleteAfter">When the key may be removed from publication entirely. It is
/// <see cref="NotAfter"/> plus the maximum lifetime of any token the key could have signed, so no live
/// token can still reference it.</param>
public sealed record AuthServiceKeyDescriptor(
    JsonWebKey Key,
    KeyLifecycleStatus Status,
    DateTimeOffset NotBefore,
    DateTimeOffset NotAfter,
    DateTimeOffset DeleteAfter);
