// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Cryptography;
using System.Text;

namespace Abblix.Oidc.Server.UnitTests.TestInfrastructure;

/// <summary>
/// Shared test helper for hashing client secrets consistently with production code.
/// Uses UTF-8 encoding to match production HashService implementation.
/// </summary>
public static class TestSecretHasher
{
    /// <summary>
    /// Hashes a client secret using SHA-512 with UTF-8 encoding.
    /// This matches the production HashService.Hash implementation.
    /// </summary>
    /// <param name="secret">The client secret to hash</param>
    /// <returns>SHA-512 hash of the UTF-8 encoded secret</returns>
    public static byte[] HashSecret(string secret)
    {
        // IMPORTANT: Use UTF8 encoding to match production code
        // See: Abblix.Oidc.Server/Features/Hashing/HashService.cs
        var encodedSecret = Encoding.UTF8.GetBytes(secret);
        return SHA512.HashData(encodedSecret);
    }
}
