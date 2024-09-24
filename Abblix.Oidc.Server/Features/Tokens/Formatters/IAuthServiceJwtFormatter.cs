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
/// Defines the interface for formatting and signing JSON Web Tokens (JWTs) within the authentication service.
/// Implementations of this interface are responsible for processing tokens, such as access tokens, refresh tokens,
/// and Registration Access Tokens, by applying the necessary cryptographic operations to produce a valid JWT.
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
