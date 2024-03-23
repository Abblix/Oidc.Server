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
