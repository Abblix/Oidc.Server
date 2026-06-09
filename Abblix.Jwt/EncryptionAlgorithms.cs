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
/// JWE algorithm identifiers ("alg" and "enc" header values) defined in RFC 7516 (JWE) and
/// RFC 7518 Sections 4 (key management) and 5 (content encryption).
/// Constants on this class are recognized by the library; some are listed but not yet supported
/// because their underlying primitives are not provided by .NET (see remarks on each member).
/// </summary>
public static class EncryptionAlgorithms
{
	/// <summary>
	/// Key management algorithms ("alg" parameter in the JWE header). These wrap or derive
	/// the Content Encryption Key (CEK) that is then used by a content encryption algorithm.
	/// </summary>
	public static class KeyManagement
	{
		/// <summary>
		/// RSAES-PKCS1-v1_5 key encryption (RFC 7518 Section 4.2). Backed by .NET <c>RSA</c>
		/// with <c>RSAEncryptionPadding.Pkcs1</c>.
		/// Kept for interoperability with legacy peers; OAEP variants should be preferred
		/// because PKCS#1 v1.5 padding is vulnerable to chosen-ciphertext attacks (Bleichenbacher).
		/// </summary>
		public const string Rsa1_5 = "RSA1_5";

		/// <summary>
		/// RSAES-OAEP with SHA-1 and MGF1-SHA-1 (RFC 7518 Section 4.3). Backed by .NET <c>RSA</c>
		/// with <c>RSAEncryptionPadding.OaepSHA1</c>.
		/// Use when interoperating with peers that have not adopted RSA-OAEP-256;
		/// otherwise prefer <see cref="RsaOaep256"/>.
		/// </summary>
		public const string RsaOaep = "RSA-OAEP";

		/// <summary>
		/// RSAES-OAEP with SHA-256 and MGF1-SHA-256 (RFC 7518 Section 4.3). Backed by .NET <c>RSA</c>
		/// with <c>RSAEncryptionPadding.OaepSHA256</c>. Recommended choice for new RSA-based JWE deployments.
		/// </summary>
		public const string RsaOaep256 = "RSA-OAEP-256";

		/// <summary>
		/// AES Key Wrap with 128-bit key.
		/// This algorithm uses the AES Key Wrap algorithm (RFC 3394) with a 128-bit key.
		/// </summary>
		/// <remarks>
		/// NOT CURRENTLY SUPPORTED: Waiting for native .NET support of RFC 3394 (plain AES Key Wrap).
		/// .NET 10 provides RFC 5649 (AES Key Wrap with Padding) which is a different algorithm.
		/// </remarks>
		public const string Aes128KW = "A128KW";

		/// <summary>
		/// AES Key Wrap with 192-bit key.
		/// This algorithm uses the AES Key Wrap algorithm (RFC 3394) with a 192-bit key.
		/// </summary>
		/// <remarks>
		/// NOT CURRENTLY SUPPORTED: Waiting for native .NET support of RFC 3394 (plain AES Key Wrap).
		/// .NET 10 provides RFC 5649 (AES Key Wrap with Padding) which is a different algorithm.
		/// </remarks>
		public const string Aes192KW = "A192KW";

		/// <summary>
		/// AES Key Wrap with 256-bit key.
		/// This algorithm uses the AES Key Wrap algorithm (RFC 3394) with a 256-bit key.
		/// </summary>
		/// <remarks>
		/// NOT CURRENTLY SUPPORTED: Waiting for native .NET support of RFC 3394 (plain AES Key Wrap).
		/// .NET 10 provides RFC 5649 (AES Key Wrap with Padding) which is a different algorithm.
		/// </remarks>
		public const string Aes256KW = "A256KW";

		/// <summary>
		/// Direct use of a shared symmetric key as the Content Encryption Key (RFC 7518 Section 4.5).
		/// No key wrap is performed and the JWE "encrypted_key" is the empty octet sequence.
		/// The shared key length must match the key size required by the chosen content encryption algorithm.
		/// </summary>
		public const string Dir = "dir";

		/// <summary>
		/// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement.
		/// This algorithm uses ECDH-ES to establish a shared secret for key encryption.
		/// </summary>
		/// <remarks>
		/// NOT CURRENTLY SUPPORTED: Requires custom implementation of Concat KDF (NIST SP 800-56A).
		/// While .NET provides native ECDiffieHellman, the Concat KDF key derivation is not available.
		/// </remarks>
		public const string EcdhEs = "ECDH-ES";

		/// <summary>
		/// ECDH-ES with AES Key Wrap using 128-bit key.
		/// Combines ECDH-ES key agreement with AES-128 Key Wrap.
		/// </summary>
		/// <remarks>
		/// NOT CURRENTLY SUPPORTED: Requires both:
		/// 1. Custom Concat KDF (NIST SP 800-56A) for ECDH key derivation
		/// 2. Native .NET support of RFC 3394 (plain AES Key Wrap)
		/// .NET 10 provides RFC 5649 (AES Key Wrap with Padding) which is a different algorithm.
		/// </remarks>
		public const string EcdhEsAes128KW = "ECDH-ES+A128KW";

		/// <summary>
		/// ECDH-ES with AES Key Wrap using 192-bit key.
		/// Combines ECDH-ES key agreement with AES-192 Key Wrap.
		/// </summary>
		/// <remarks>
		/// NOT CURRENTLY SUPPORTED: Requires both:
		/// 1. Custom Concat KDF (NIST SP 800-56A) for ECDH key derivation
		/// 2. Native .NET support of RFC 3394 (plain AES Key Wrap)
		/// .NET 10 provides RFC 5649 (AES Key Wrap with Padding) which is a different algorithm.
		/// </remarks>
		public const string EcdhEsAes192KW = "ECDH-ES+A192KW";

		/// <summary>
		/// ECDH-ES with AES Key Wrap using 256-bit key.
		/// Combines ECDH-ES key agreement with AES-256 Key Wrap.
		/// </summary>
		/// <remarks>
		/// NOT CURRENTLY SUPPORTED: Requires both:
		/// 1. Custom Concat KDF (NIST SP 800-56A) for ECDH key derivation
		/// 2. Native .NET support of RFC 3394 (plain AES Key Wrap)
		/// .NET 10 provides RFC 5649 (AES Key Wrap with Padding) which is a different algorithm.
		/// </remarks>
		public const string EcdhEsAes256KW = "ECDH-ES+A256KW";

		/// <summary>
		/// AES-GCM Key Wrap with a 128-bit key (RFC 7518 Section 4.7). Backed by .NET <c>AesGcm</c>.
		/// Output is laid out as <c>IV (96 bits) || Ciphertext || Authentication Tag (128 bits)</c>.
		/// </summary>
		public const string Aes128Gcmkw = "A128GCMKW";

		/// <summary>
		/// AES-GCM Key Wrap with a 192-bit key (RFC 7518 Section 4.7). Backed by .NET <c>AesGcm</c>.
		/// </summary>
		public const string Aes192Gcmkw = "A192GCMKW";

		/// <summary>
		/// AES-GCM Key Wrap with a 256-bit key (RFC 7518 Section 4.7). Backed by .NET <c>AesGcm</c>.
		/// Recommended choice when both peers can share a symmetric key.
		/// </summary>
		public const string Aes256Gcmkw = "A256GCMKW";

		/// <summary>
		/// PBES2 with HMAC SHA-256 and AES-128 Key Wrap (RFC 7518 Section 4.8).
		/// </summary>
		/// <remarks>
		/// NOT CURRENTLY SUPPORTED: requires PBKDF2 plus AES Key Wrap (RFC 3394), neither of which
		/// is exposed natively by .NET in the form RFC 7518 mandates.
		/// </remarks>
		public const string Pbes2HmacSha256Aes128KW = "PBES2-HS256+A128KW";

		/// <summary>
		/// PBES2 with HMAC SHA-384 and AES-192 Key Wrap (RFC 7518 Section 4.8).
		/// </summary>
		/// <remarks>
		/// NOT CURRENTLY SUPPORTED. See <see cref="Pbes2HmacSha256Aes128KW"/>.
		/// </remarks>
		public const string Pbes2HmacSha384Aes192KW = "PBES2-HS384+A192KW";

		/// <summary>
		/// PBES2 with HMAC SHA-512 and AES-256 Key Wrap (RFC 7518 Section 4.8).
		/// </summary>
		/// <remarks>
		/// NOT CURRENTLY SUPPORTED. See <see cref="Pbes2HmacSha256Aes128KW"/>.
		/// </remarks>
		public const string Pbes2HmacSha512Aes256KW = "PBES2-HS512+A256KW";
	}

	/// <summary>
	/// Content encryption algorithms ("enc" parameter in the JWE header). These encrypt the
	/// JWE payload using the Content Encryption Key produced by the key management algorithm.
	/// </summary>
	public static class ContentEncryption
	{
		/// <summary>
		/// AES-128-CBC with HMAC-SHA-256 authentication (RFC 7518 Section 5.2). Backed by .NET
		/// <c>Aes</c> in CBC/PKCS7 mode and <c>HMACSHA256</c>; the 256-bit CEK is split into a
		/// 128-bit MAC key and a 128-bit AES key.
		/// </summary>
		public const string Aes128CbcHmacSha256 = "A128CBC-HS256";

		/// <summary>
		/// AES-192-CBC with HMAC-SHA-384 authentication (RFC 7518 Section 5.2). Backed by .NET
		/// <c>Aes</c> in CBC/PKCS7 mode and <c>HMACSHA384</c>; uses a 384-bit CEK.
		/// </summary>
		public const string Aes192CbcHmacSha384 = "A192CBC-HS384";

		/// <summary>
		/// AES-256-CBC with HMAC-SHA-512 authentication (RFC 7518 Section 5.2). Backed by .NET
		/// <c>Aes</c> in CBC/PKCS7 mode and <c>HMACSHA512</c>; uses a 512-bit CEK.
		/// Default content encryption used by this library when issuing encrypted tokens.
		/// </summary>
		public const string Aes256CbcHmacSha512 = "A256CBC-HS512";

		/// <summary>
		/// AES-128 in Galois/Counter Mode (RFC 7518 Section 5.3). Backed by .NET <c>AesGcm</c>
		/// with a 96-bit IV and 128-bit authentication tag. Single-pass authenticated encryption.
		/// </summary>
		public const string Aes128Gcm = "A128GCM";

		/// <summary>
		/// AES-192 in Galois/Counter Mode (RFC 7518 Section 5.3). Backed by .NET <c>AesGcm</c>
		/// with a 96-bit IV and 128-bit authentication tag.
		/// </summary>
		public const string Aes192Gcm = "A192GCM";

		/// <summary>
		/// AES-256 in Galois/Counter Mode (RFC 7518 Section 5.3). Backed by .NET <c>AesGcm</c>
		/// with a 96-bit IV and 128-bit authentication tag. Recommended where peers support GCM.
		/// </summary>
		public const string Aes256Gcm = "A256GCM";
	}
}
