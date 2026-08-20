// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
