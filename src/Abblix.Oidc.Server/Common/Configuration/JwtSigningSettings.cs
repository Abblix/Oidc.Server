// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// The signing settings for a JWT the authorization server issues for itself. Reused, one instance per
/// service token type, so each type carries its own explicit JWS <c>alg</c> and signing-key selection
/// instead of the previously hardcoded RS256.
/// </summary>
public record JwtSigningSettings
{
    /// <summary>
    /// The JWS signing algorithm (the <c>alg</c> header value, e.g. <c>RS256</c>, <c>ES256</c>).
    /// Defaults to <see cref="SigningAlgorithms.RS256"/> so that, left unset, the token is byte-identical
    /// to what the server issued before this setting existed.
    /// </summary>
    public string Algorithm { get; set; } = SigningAlgorithms.RS256;

    /// <summary>
    /// The <c>kid</c> of the signing key to use. When <c>null</c> the first key matching
    /// <see cref="Algorithm"/> is chosen (RFC 7517 Section 4.4); when set, the key with this identifier is
    /// pinned and its <c>kid</c> is emitted in the JWS header.
    /// </summary>
    public string? KeyId { get; set; }
}
