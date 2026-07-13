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

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// The encryption settings for a JWT the authorization server issues for itself. Reused, one instance per
/// service token type. The mere presence of this block on a token type is the opt-in to encrypt that type:
/// without it the token is signed only.
/// </summary>
/// <remarks>
/// The content-encryption algorithm (the JWE <c>enc</c>) is not per-key, so it is not carried here; it stays
/// on the root <see cref="OidcOptions.DefaultContentEncryptionAlgorithm"/>.
/// </remarks>
public record JwtEncryptionSettings
{
    /// <summary>
    /// The JWE key-management algorithm (the <c>alg</c> header value, e.g. <c>RSA-OAEP-256</c>). When
    /// <c>null</c> it is derived from the selected encryption key's declared <c>alg</c> (RFC 7517
    /// Section 4.4), falling back to <c>RSA-OAEP-256</c> when the key declares none.
    /// </summary>
    public string? Algorithm { get; set; }

    /// <summary>
    /// The <c>kid</c> of the encryption key to use. When <c>null</c> the first configured encryption key is
    /// chosen; when set, the key with this identifier is pinned.
    /// </summary>
    public string? KeyId { get; set; }
}
