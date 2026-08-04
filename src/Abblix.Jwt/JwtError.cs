// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/Oidc.Server. All development and modifications
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
/// for a human-readable explanation. Categories let callers branch on the failure cause
/// without parsing the description string.
/// </summary>
public enum JwtError
{
	/// <summary>
	/// The token cannot be accepted but does not fall into a more specific category below
	/// (for example, a missing or invalid issuer/audience/lifetime claim).
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

	/// <summary>
	/// The compact JWS / JWE serialisation failed to parse: wrong dot-separated-segment
	/// count, base64url decode failure, or the header/payload is not a JSON object.
	/// </summary>
	MalformedToken,

	/// <summary>
	/// The <c>alg</c> header parameter is missing, names the unsecured <c>none</c>
	/// algorithm where signed tokens are required, or falls outside the caller's
	/// configured <see cref="ValidationParameters.AllowedSigningAlgorithms"/> whitelist.
	/// </summary>
	InvalidAlgorithm,

	/// <summary>
	/// The <c>typ</c> header parameter is missing or does not match the caller's
	/// <see cref="ValidationParameters.ExpectedTokenTypes"/> (RFC 8725 §3.11
	/// token-type confusion guard).
	/// </summary>
	InvalidTokenType,

	/// <summary>
	/// A JOSE header parameter is malformed or violates a structural rule: the embedded
	/// <c>jwk</c> is not a valid JWK, the <c>crit</c> array is malformed or names an
	/// unknown extension, or a required header is missing for the chosen trust model.
	/// </summary>
	InvalidHeader,

	/// <summary>
	/// The JWS signature does not verify under the resolved signing key.
	/// </summary>
	InvalidSignature,
}
