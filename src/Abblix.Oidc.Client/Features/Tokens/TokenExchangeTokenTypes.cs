// Abblix OIDC Client Library
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

namespace Abblix.Oidc.Client.Features.Tokens;

/// <summary>
/// Token type identifiers for RFC 8693 Token Exchange. Used as the value of the wire-level
/// <c>subject_token_type</c>, <c>actor_token_type</c> and <c>requested_token_type</c> parameters, and
/// echoed back in the response's <c>issued_token_type</c>.
/// </summary>
/// <remarks>
/// These are not an enumeration of what a provider will accept. RFC 8693 section 3 registers the identifiers
/// and leaves it to each deployment to say which ones it takes; a provider is also free to define its own.
/// The parameters carrying them are therefore plain strings, and this class only spares the caller from
/// spelling out the registered ones.
/// </remarks>
public static class TokenExchangeTokenTypes
{
    /// <summary>OAuth 2.0 access token, opaque or JWT. RFC 8693 section 3.</summary>
    public const string AccessToken = "urn:ietf:params:oauth:token-type:access_token";

    /// <summary>OAuth 2.0 refresh token. RFC 8693 section 3.</summary>
    public const string RefreshToken = "urn:ietf:params:oauth:token-type:refresh_token";

    /// <summary>OpenID Connect ID Token, always a JWT. RFC 8693 section 3.</summary>
    public const string IdToken = "urn:ietf:params:oauth:token-type:id_token";

    /// <summary>JSON Web Token of unspecified profile. RFC 8693 section 3.</summary>
    public const string Jwt = "urn:ietf:params:oauth:token-type:jwt";

    /// <summary>SAML 1.1 assertion. RFC 8693 section 3.</summary>
    public const string Saml1 = "urn:ietf:params:oauth:token-type:saml1";

    /// <summary>SAML 2.0 assertion. RFC 8693 section 3.</summary>
    public const string Saml2 = "urn:ietf:params:oauth:token-type:saml2";
}
