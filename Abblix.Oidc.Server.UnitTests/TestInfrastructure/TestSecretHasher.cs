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
