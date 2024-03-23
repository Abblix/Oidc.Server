// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

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
