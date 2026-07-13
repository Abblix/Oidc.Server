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
/// The signing and encryption settings for one type of JWT the authorization server issues for itself
/// (access, refresh, registration access or initial access token). The same shape is reused for every type
/// via <see cref="ServiceTokensOptions"/>.
/// </summary>
public record ServiceTokenOptions
{
    /// <summary>
    /// The signing settings, always present. Left at its defaults it signs with RS256 and lets the server
    /// choose the first matching key, reproducing the output the server produced before this option existed.
    /// </summary>
    public JwtSigningSettings Signing { get; set; } = new();

    /// <summary>
    /// Whether to encrypt this token type to the server's own encryption key. <c>true</c> (the default)
    /// encrypts it whenever a server encryption key is configured and otherwise signs it only, matching the
    /// behavior of prior versions. Set to <c>false</c> to keep the token signed only even when an encryption
    /// key exists — for example to keep the access token readable by external resource servers that validate
    /// it against the published key set.
    /// </summary>
    public bool Encrypt { get; set; } = true;

    /// <summary>
    /// How this token type is encrypted when <see cref="Encrypt"/> is on and a server encryption key is
    /// available: the JWE key-management algorithm and the key to use. Left at its defaults it derives the
    /// algorithm from the selected key and takes the first configured encryption key.
    /// </summary>
    public JwtEncryptionSettings Encryption { get; set; } = new();
}
