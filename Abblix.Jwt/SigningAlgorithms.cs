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
/// JWS signing algorithm identifiers ("alg" header values) defined in RFC 7518 Section 3.
/// Used to indicate how a JWT was signed and to look up the matching signer or verifier.
/// </summary>
public static class SigningAlgorithms
{
	/// <summary>
	/// Unsecured JWS ("none") per RFC 7515 Section 6: no digital signature or MAC is applied.
	/// The token's integrity is therefore not protected; callers must reject unsigned tokens
	/// unless integrity is guaranteed by another channel.
	/// </summary>
	public const string None = "none";

	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-256 (RFC 7518 Section 3.3). Backed by .NET <c>RSA</c>
	/// with <c>RSASignaturePadding.Pkcs1</c>. Widely deployed default for OIDC ID tokens.
	/// </summary>
	public const string RS256 = "RS256";

	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-384 (RFC 7518 Section 3.3). Same construction as RS256
	/// with a stronger hash; backed by .NET <c>RSA</c> with <c>RSASignaturePadding.Pkcs1</c>.
	/// </summary>
	public const string RS384 = "RS384";

	/// <summary>
	/// RSASSA-PKCS1-v1_5 with SHA-512 (RFC 7518 Section 3.3). Same construction as RS256
	/// with SHA-512; backed by .NET <c>RSA</c> with <c>RSASignaturePadding.Pkcs1</c>.
	/// </summary>
	public const string RS512 = "RS512";

	/// <summary>
	/// RSASSA-PSS with SHA-256 and MGF1 (RFC 7518 Section 3.5). Backed by .NET <c>RSA</c>
	/// with <c>RSASignaturePadding.Pss</c>. Preferred over RS256 when both sides support PSS,
	/// because PSS has a tighter security reduction.
	/// </summary>
	public const string PS256 = "PS256";

	/// <summary>
	/// RSASSA-PSS with SHA-384 and MGF1 (RFC 7518 Section 3.5). Backed by .NET <c>RSA</c>
	/// with <c>RSASignaturePadding.Pss</c>.
	/// </summary>
	public const string PS384 = "PS384";

	/// <summary>
	/// RSASSA-PSS with SHA-512 and MGF1 (RFC 7518 Section 3.5). Backed by .NET <c>RSA</c>
	/// with <c>RSASignaturePadding.Pss</c>.
	/// </summary>
	public const string PS512 = "PS512";

	/// <summary>
	/// ECDSA on curve P-256 with SHA-256 (RFC 7518 Section 3.4). Backed by .NET <c>ECDsa</c>
	/// using <c>DSASignatureFormat.IeeeP1363FixedFieldConcatenation</c>.
	/// Produces 64-byte signatures and is significantly smaller than RSA equivalents.
	/// </summary>
	public const string ES256 = "ES256";

	/// <summary>
	/// ECDSA on curve P-384 with SHA-384 (RFC 7518 Section 3.4). Backed by .NET <c>ECDsa</c>
	/// in IEEE P1363 format; produces 96-byte signatures.
	/// </summary>
	public const string ES384 = "ES384";

	/// <summary>
	/// ECDSA on curve P-521 with SHA-512 (RFC 7518 Section 3.4). Backed by .NET <c>ECDsa</c>
	/// in IEEE P1363 format; produces 132-byte signatures.
	/// Note that the curve is P-521 (521 bits) although the algorithm name is "ES512".
	/// </summary>
	public const string ES512 = "ES512";

	/// <summary>
	/// HMAC with SHA-256 (RFC 7518 Section 3.2). Backed by .NET <c>HMACSHA256</c> with
	/// constant-time signature comparison. Requires a shared symmetric key of at least 256 bits.
	/// Suitable only when issuer and verifier can both be trusted with the secret.
	/// </summary>
	public const string HS256 = "HS256";

	/// <summary>
	/// HMAC with SHA-384 (RFC 7518 Section 3.2). Backed by .NET <c>HMACSHA384</c>;
	/// requires a shared symmetric key of at least 384 bits.
	/// </summary>
	public const string HS384 = "HS384";

	/// <summary>
	/// HMAC with SHA-512 (RFC 7518 Section 3.2). Backed by .NET <c>HMACSHA512</c>;
	/// requires a shared symmetric key of at least 512 bits.
	/// </summary>
	public const string HS512 = "HS512";
}
