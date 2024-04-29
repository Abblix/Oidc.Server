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

namespace Abblix.Oidc.Server.Features.RandomGenerators;

/// <summary>
/// Defines a contract for generating unique authorization codes for use in OAuth 2.0 authorization code flows.
/// Implementations of this interface should ensure that the generated codes are cryptographically secure
/// and suitable for one-time use in authenticating and authorizing access.
/// </summary>
public interface IAuthorizationCodeGenerator
{
    /// <summary>
    /// Generates a unique, cryptographically secure authorization code.
    /// </summary>
    /// <returns>A string representing a unique authorization code.</returns>
    string GenerateAuthorizationCode();
}
