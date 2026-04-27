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
/// High-level categories of JWT processing failures returned by the validator and by callers
/// that consume validated tokens. Pair with <see cref="JwtValidationError.ErrorDescription"/>
/// for a human-readable explanation.
/// </summary>
public enum JwtError
{
	/// <summary>
	/// The token cannot be accepted: malformed serialization, missing required header
	/// parameters, signature mismatch, expired lifetime, wrong issuer or audience, etc.
	/// </summary>
	InvalidToken,

	/// <summary>
	/// The token is well-formed and otherwise valid, but it has already been redeemed
	/// in a context that allows only single use (for example, an authorization code or a
	/// one-time login link).
	/// </summary>
	TokenAlreadyUsed,

	/// <summary>
	/// The token has been explicitly revoked by the issuer (for example, after sign-out,
	/// password change, or administrative action) and must no longer be honored.
	/// </summary>
	TokenRevoked,
}
