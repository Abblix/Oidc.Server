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

namespace Abblix.Oidc.Server.Features.UserInfo;

/// <summary>
/// Configuration for pairwise subject identifier generation.
/// The salt is a server-side secret that prevents external computation of pairwise identifiers,
/// ensuring that even with knowledge of the user's real subject and the client ID,
/// an attacker cannot derive the pairwise identifier.
/// </summary>
public record PairwiseSubjectSettings
{
    /// <summary>
    /// A base64-encoded cryptographic salt used in HMAC computation for pairwise identifiers.
    /// This value MUST be kept secret, generated once, and never changed
    /// (changing it would invalidate all existing pairwise identifiers).
    /// Minimum recommended length: 32 bytes (256 bits) before encoding.
    /// </summary>
    public required string Salt { get; init; }

    /// <summary>
    /// The HMAC algorithm used to compute pairwise subject identifiers.
    /// Defaults to HMAC-SHA256. Supported algorithms: SHA256, SHA384, SHA512, SHA1.
    /// </summary>
    public HashAlgorithmName HashAlgorithm { get; init; } = HashAlgorithmName.SHA256;
}
