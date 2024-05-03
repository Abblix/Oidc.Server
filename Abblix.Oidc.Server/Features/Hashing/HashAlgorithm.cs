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

namespace Abblix.Oidc.Server.Features.Hashing;

/// <summary>
/// Specifies the hash algorithms supported for hashing operations.
/// </summary>
public enum HashAlgorithm
{
    /// <summary>
    /// Represents the SHA-256 hash algorithm.
    /// SHA-256 (Secure Hash Algorithm 256-bit) is a cryptographic hash function
    /// that produces a 256-bit hash value, widely used for data integrity verification.
    /// </summary>
    Sha256,

    /// <summary>
    /// Represents the SHA-512 hash algorithm.
    /// SHA-512 (Secure Hash Algorithm 512-bit) is a cryptographic hash function
    /// that produces a 512-bit hash value. It is used in various security applications
    /// and protocols, including TLS and SSL, PGP, SSH, and IPsec.
    /// </summary>
    Sha512,
}
