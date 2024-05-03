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
/// Defines an interface for generating unique identifiers for JSON Web Tokens (JWTs).
/// This interface abstracts the details of how JWT IDs are generated, allowing for different
/// implementations that can provide various methods of generating unique and secure token identifiers.
/// </summary>
public interface ITokenIdGenerator
{
	/// <summary>
	/// Generates a new unique identifier for a JWT. The specific implementation determines the format
	/// and characteristics of the generated ID, such as its length, randomness, and URL-safety.
	/// </summary>
	/// <returns>A unique identifier suitable for use as a JWT ID.</returns>
	string GenerateTokenId();
}
