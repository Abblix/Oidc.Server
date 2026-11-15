// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.RequestObject;

/// <summary>
/// Tells an unsecured request object from a signed one.
/// </summary>
internal static class UnsecuredRequestObject
{
    /// <summary>
    /// OpenID Connect Core 1.0 section 6.1: "When it is unsecured, this is indicated by use of the none algorithm [JWA]
    /// in the JOSE Header". Compared ordinally, as a case variant of "none" names no algorithm and is refused as such.
    /// </summary>
    public static bool Is(JsonWebToken requestObject)
        => string.Equals(requestObject.Header.Algorithm, SigningAlgorithms.None, StringComparison.Ordinal);
}
