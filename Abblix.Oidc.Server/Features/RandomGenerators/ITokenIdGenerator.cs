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
/// Produces unique identifiers for JSON Web Tokens, used as the <c>jti</c> claim defined in RFC 7519 §4.1.7.
/// A unique <c>jti</c> per token is required to support replay detection and one-time token semantics, so
/// implementations must generate values with sufficient entropy to make collisions and guessing impractical.
/// </summary>
public interface ITokenIdGenerator
{
	/// <summary>
	/// Generates a new unique identifier suitable for the <c>jti</c> claim of a JWT.
	/// </summary>
	/// <returns>A unique identifier suitable for use as a JWT ID.</returns>
	string GenerateTokenId();
}
