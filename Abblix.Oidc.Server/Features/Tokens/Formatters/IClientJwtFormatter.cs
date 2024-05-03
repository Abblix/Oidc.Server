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
using Abblix.Oidc.Server.Features.ClientInformation;

namespace Abblix.Oidc.Server.Features.Tokens.Formatters;

/// <summary>
/// Formats JWTs (JSON Web Tokens) issued to clients of the authentication service.
/// Implements the formatting of JWT object model to a string format according RFC 7519.
/// </summary>
public interface IClientJwtFormatter
{
    /// <summary>
    /// Formats a JWT for a client using the provided token and client information.
    /// </summary>
    /// <param name="token">The JWT token to format.</param>
    /// <param name="clientInfo">The client information.</param>
    /// <returns>The formatted JWT string.</returns>
    Task<string> FormatAsync(JsonWebToken token, ClientInfo clientInfo);
}
