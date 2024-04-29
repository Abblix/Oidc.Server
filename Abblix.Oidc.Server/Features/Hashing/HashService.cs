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

namespace Abblix.Oidc.Server.Features.Hashing;

/// <summary>
/// Provides hashing functionality for various types of data, including but not limited to client secrets,
/// in OAuth 2.0 and OpenID Connect authentication flows.
/// This class supports SHA-256 and SHA-512 hashing algorithms to securely hash data.
/// </summary>
/// <remarks>
/// Hashing data, especially secrets, enhances privacy and security by ensuring that only a hashed version
/// of the data is stored. In the event of a data breach, attackers cannot access the actual data, such as
/// client secrets, thereby reducing the risk of exploitation.
/// </remarks>
public class HashService : IHashService
{
    /// <summary>
    /// Computes a hash for the provided data using the specified hash algorithm.
    /// </summary>
    /// <param name="algorithm">The hash algorithm to use (e.g., SHA-256 or SHA-512).</param>
    /// <param name="data">The data to hash.</param>
    /// <returns>A byte array containing the hash of the data.</returns>
    /// <exception cref="ArgumentOutOfRangeException">Thrown when the specified hash algorithm is not supported.</exception>
    public byte[] Sha(HashAlgorithm algorithm, string data)
    {
        var bytes = Encoding.ASCII.GetBytes(data);
        return algorithm switch
        {
            HashAlgorithm.Sha256 => SHA256.HashData(bytes),
            HashAlgorithm.Sha512 => SHA512.HashData(bytes),

            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm,
                $"The hash algorithm {algorithm} is not supported"),
        };
    }
}
