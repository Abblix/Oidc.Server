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

namespace Abblix.Oidc.Server.Features.Hashing;

/// <summary>
/// Offers hashing functionality for data using various Secure Hash Algorithms (SHA).
/// This service is essential for securely storing and comparing sensitive information
/// like passwords or client secrets without exposing the actual values.
/// </summary>
public interface IHashService
{
    /// <summary>
    /// Generates a hash for the specified data using a chosen SHA algorithm.
    /// This method provides a way to securely hash sensitive data, such as secrets
    /// or passwords, ensuring that the original data cannot be easily derived from the hash.
    /// </summary>
    /// <param name="algorithm">Specifies the SHA algorithm to use for hashing, such as SHA-256 or SHA-512.</param>
    /// <param name="data">The data to hash. Typically, this is sensitive information that needs secure handling.</param>
    /// <returns>A byte array containing the hash of the input data.</returns>
    /// <remarks>
    /// It is crucial to select an appropriate SHA algorithm based on security requirements and performance considerations.
    /// The hash output is ideal for verifying data integrity and authenticating users or clients without storing or transmitting
    /// sensitive plain-text data.
    /// </remarks>
    byte[] Sha(HashAlgorithm algorithm, string data);
}
