// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

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
    /// Whether to encrypt this token type to the server's own encryption key.
    /// </summary>
    /// <remarks>
    /// Three states, and the difference between two of them decides how a missing key is answered:
    /// <list type="bullet">
    /// <item><c>false</c> keeps the token a signed JWS even when an encryption key exists, for example to keep
    /// the access token readable by external resource servers that validate it against the published key set.
    /// The server's encryption keys are not resolved at all.</item>
    /// <item><c>true</c> requires encryption. If no encryption key can be resolved the server refuses to issue
    /// the token rather than falling back to a signed JWS, because a host that asked for confidentiality and
    /// silently did not get it has no way to find out.</item>
    /// <item><c>null</c>, the default, states nothing: the token is encrypted when a server encryption key is
    /// available and signed only when none is, which is the behaviour of prior versions. A host that never
    /// touched this setting therefore sees no change and no new failure.</item>
    /// </list>
    /// </remarks>
    public bool? Encrypt { get; set; }

    /// <summary>
    /// How this token type is encrypted when <see cref="Encrypt"/> is on and a server encryption key is
    /// available: the JWE key-management algorithm and the key to use. Left at its defaults it derives the
    /// algorithm from the selected key and takes the first configured encryption key.
    /// </summary>
    public JwtEncryptionSettings Encryption { get; set; } = new();
}
