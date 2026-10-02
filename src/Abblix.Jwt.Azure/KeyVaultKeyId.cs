// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Jwt.Azure;

/// <summary>
/// A published <c>kid</c> split back into the name and version the SDK addresses a key by.
/// </summary>
/// <param name="Name">The Key Vault key name.</param>
/// <param name="Version">The key version.</param>
internal readonly record struct KeyVaultKeyId(string Name, string Version)
{
    /// <summary>
    /// Splits a published <c>kid</c>.
    /// </summary>
    /// <remarks>
    /// The kid is minted as <c>name/version</c> when the versions are published, and a Key Vault key name cannot
    /// contain a slash, so the split is unambiguous. A kid without a version is not one this client published.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The kid is not one this client published.</exception>
    public static KeyVaultKeyId Parse(string keyId)
    {
        var separator = keyId.IndexOf('/');
        if (separator <= 0 || separator == keyId.Length - 1)
        {
            throw new InvalidOperationException(
                $"Malformed external key id '{keyId}': expected '<name>/<version>', which is what this client " +
                "publishes as the kid of each key version.");
        }

        return new KeyVaultKeyId(keyId[..separator], keyId[(separator + 1)..]);
    }
}
