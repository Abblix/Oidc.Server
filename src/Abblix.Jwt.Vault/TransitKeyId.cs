// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;

namespace Abblix.Jwt.Vault;

/// <summary>
/// The published kid <c>&lt;transit key name&gt;:&lt;version&gt;</c>, split to address the Transit key and pin
/// the version for a private operation.
/// </summary>
/// <param name="Name">The Transit key name.</param>
/// <param name="Version">The key version the kid names.</param>
internal readonly record struct TransitKeyId(string Name, int Version)
{
    /// <summary>
    /// Splits a published kid. Transit key names contain no colon, so the last colon is the separator.
    /// </summary>
    /// <exception cref="InvalidOperationException">The kid is not one this custodian published.</exception>
    public static TransitKeyId Parse(string keyId)
    {
        var separator = keyId.LastIndexOf(':');
        if (separator > 0 && int.TryParse(
                keyId.AsSpan(separator + 1), NumberStyles.None, CultureInfo.InvariantCulture, out var version))
            return new TransitKeyId(keyId[..separator], version);

        throw new InvalidOperationException(
            $"Malformed external key id '{keyId}'; expected '<name>:<version>' from " +
            $"{nameof(TransitCustodian.GetKeyVersionsAsync)}.");
    }
}
