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


namespace Abblix.Oidc.Client.Features.Revocation;

/// <summary>
/// The values of the <c>token_type_hint</c> parameter, as they appear on the wire.
/// </summary>
/// <remarks>
/// RFC 7009 section 2.1 defines these two and registers them in the OAuth Token Type Hints registry. The
/// hint only tells the provider which store to look in first: section 2.2 says "an invalid token type hint
/// value is ignored by the authorization server and does not influence the revocation response", so a wrong
/// hint costs a lookup, not a revocation.
/// </remarks>
public static class TokenTypeHints
{
    /// <summary>
    /// The token being revoked is an access token.
    /// </summary>
    public const string AccessToken = "access_token";

    /// <summary>
    /// The token being revoked is a refresh token.
    /// </summary>
    public const string RefreshToken = "refresh_token";
}
