// Abblix OIDC Server Library
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

using Abblix.Jwt;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Serializes a <see cref="JsonWebToken"/> minted by the authorization server itself (access
/// tokens, refresh tokens, Registration Access Tokens) into a compact JWS form (RFC 7515) using
/// the server's signing keys, optionally wrapping the result in a JWE (RFC 7516) when an
/// encryption key is available.
/// </summary>
public interface IAuthServiceJwtFormatter
{
    /// <summary>
    /// Formats and signs a JWT for use within the authentication service, applying cryptographic operations such as
    /// signing and optionally encrypting the token based on the specified requirements.
    /// </summary>
    /// <param name="token">The JSON Web Token (JWT) to be formatted and signed, potentially also encrypted.</param>
    /// <returns>A task representing the asynchronous operation, which results in the JWT formatted as a string.
    /// </returns>
    Task<string> FormatAsync(JsonWebToken token);
}
