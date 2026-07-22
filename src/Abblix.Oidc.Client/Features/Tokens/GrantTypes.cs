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
/// The grant types this client presents at the token endpoint, as they appear on the wire.
/// </summary>
public static class GrantTypes
{
    /// <summary>Exchanging an authorization code for tokens.</summary>
    public const string AuthorizationCode = "authorization_code";

    /// <summary>Trading a refresh token for a fresh set.</summary>
    public const string RefreshToken = "refresh_token";

    /// <summary>
    /// Asking for a token on the client's own behalf, with no user involved (RFC 6749 section 4.4).
    /// </summary>
    public const string ClientCredentials = "client_credentials";
}
