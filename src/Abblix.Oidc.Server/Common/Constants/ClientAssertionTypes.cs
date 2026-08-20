// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Provides constants for client assertion types used in OAuth 2.0.
/// </summary>
public static class ClientAssertionTypes
{
    /// <summary>
    /// URN identifying a JWT bearer token as the client authentication assertion at the token endpoint,
    /// per RFC 7523 (JSON Web Token Profile for OAuth 2.0 Client Authentication and Authorization Grants).
    /// Submitted as the <c>client_assertion_type</c> parameter together with the signed JWT in
    /// <c>client_assertion</c>.
    /// </summary>
    public const string JwtBearer = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer";
}
