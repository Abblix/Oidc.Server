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

namespace Abblix.Jwt;

/// <summary>
/// Enumerates the different types of JWT-related errors.
/// </summary>
public enum JwtError
{
	/// <summary>
	/// Indicates that the token is invalid.
	/// This can be due to various reasons such as incorrect format, signature issues, or payload inconsistencies.
	/// </summary>
	InvalidToken,

	/// <summary>
	/// Indicates that the token has already been used.
	/// This error is typically encountered in scenarios where tokens are meant for single use, such as one-time authorization tokens.
	/// </summary>
	TokenAlreadyUsed,

	/// <summary>
	/// Indicates that the token has been revoked.
	/// A revoked token is no longer valid for use, typically due to security reasons or changes in the access rights of the user.
	/// </summary>
	TokenRevoked,
}
