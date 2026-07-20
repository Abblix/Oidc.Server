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

namespace Abblix.Jwt.Vault;

/// <summary>
/// Points the key ring at a Vault / OpenBao KV version 2 secrets engine, on the same server the custodian uses:
/// its address and token come from <see cref="VaultTransitOptions"/>, since one Vault holds both the key that
/// protects the ring and the ring itself.
/// </summary>
/// <remarks>
/// The engine must be KV VERSION 2. Only v2 offers the check-and-set write this ring is built on, and it is what
/// makes exactly one pod win a period: v1 overwrites blindly, which would let two pods each believe they minted
/// the period's key.
/// </remarks>
public sealed class VaultKeyValueOptions
{
    /// <summary>Mount path of the KV v2 engine (the conventional mount is <c>secret</c>).</summary>
    public string Mount { get; set; } = "secret";

    /// <summary>
    /// The path under the mount that holds the ring; each key becomes one secret beneath it.
    /// </summary>
    public string Path { get; set; } = "oidc-keyring";
}
