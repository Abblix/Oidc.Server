// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common.Constants;

/// <summary>
/// Token type identifiers for RFC 8693 Token Exchange. Used as the value of the wire-level
/// <c>subject_token_type</c>, <c>actor_token_type</c>, and <c>requested_token_type</c> parameters,
/// and echoed back in the token response's <c>issued_token_type</c> field.
/// </summary>
public static class TokenExchangeTokenTypes
{
    /// <summary>OAuth 2.0 access token (opaque or JWT). RFC 8693 section 3.</summary>
    public const string AccessToken = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>OAuth 2.0 refresh token. RFC 8693 section 3.</summary>
    public const string RefreshToken = "urn:ietf:params:oauth:token-type:refresh_token";

    /// <summary>OpenID Connect ID token (always a JWT). RFC 8693 section 3.</summary>
    public const string IdToken = "urn:ietf:params:oauth:token-type:id_token";

    /// <summary>JSON Web Token of unspecified profile. RFC 8693 section 3.</summary>
    public const string Jwt = "urn:ietf:params:oauth:token-type:jwt";

    /// <summary>SAML 1.1 assertion. RFC 8693 section 3 -- listed for completeness;
    /// not currently issued or accepted by this library.</summary>
    public const string Saml1 = "urn:ietf:params:oauth:token-type:saml1";

    /// <summary>SAML 2.0 assertion. RFC 8693 section 3 -- listed for completeness;
    /// not currently issued or accepted by this library.</summary>
    public const string Saml2 = "urn:ietf:params:oauth:token-type:saml2";
}
