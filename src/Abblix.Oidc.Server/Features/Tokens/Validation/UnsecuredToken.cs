// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.Tokens.Validation;

/// <summary>
/// Tells an unsecured token from a signed one.
/// </summary>
internal static class UnsecuredToken
{
    /// <summary>
    /// RFC 7519 section 6: "An Unsecured JWT is a JWS using the "alg" Header Parameter value "none"", which a JWE
    /// carrying a claims set rather than a signed JWT is given once decrypted. Compared ordinally, as a case variant of
    /// "none" names no algorithm and is refused as such.
    /// </summary>
    public static bool Is(JsonWebToken token)
        => string.Equals(token.Header.Algorithm, SigningAlgorithms.None, StringComparison.Ordinal);
}
