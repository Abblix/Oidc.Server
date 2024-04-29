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
/// Formats and signs JSON Web Tokens (JWTs) according RFC 7519 for the authentication service itself.
/// These tokens are utilized in various API endpoints for authentication and authorization purposes.
/// </summary>
public interface IAuthServiceJwtFormatter
{
    /// <summary>
    /// Formats a JWT asynchronously for the authentication service itself.
    /// </summary>
    /// <param name="token">The JWT to format.</param>
    /// <returns>A formatted JWT as a string.</returns>
    Task<string> FormatAsync(JsonWebToken token);
}
