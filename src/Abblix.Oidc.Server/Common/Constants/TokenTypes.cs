// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Represents token types used in authentication and authorization.
/// </summary>
public static class TokenTypes
{
    /// <summary>
    /// Indicates the Basic authentication scheme per RFC 7617, where client credentials
    /// are transmitted as a Base64-encoded <c>client_id:client_secret</c> pair.
    /// </summary>
    public const string Basic = "Basic";

    /// <summary>
    /// Indicates the Bearer token type, often used in OAuth 2.0 for securing API requests.
    /// </summary>
    public const string Bearer = "Bearer";

    /// <summary>
    /// Indicates a DPoP-bound token type per RFC 9449 section 7.1: the access token is locked to
    /// a specific proof-of-possession key and the client MUST present a fresh DPoP proof
    /// on every resource-server request. Carries a <c>cnf.jkt</c> confirmation claim equal
    /// to the JWK thumbprint of the binding key.
    /// </summary>
    public const string DPoP = "DPoP";
}
