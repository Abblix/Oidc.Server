// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
