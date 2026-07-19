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
