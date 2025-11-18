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
/// Provides constants for various encryption algorithms used in JWE (JSON Web Encryption) operations.
/// These algorithms are defined in RFC 7516 (JWE) and RFC 7518 (JWA).
/// </summary>
public static class EncryptionAlgorithms
{
	/// <summary>
	/// Key Management Algorithms (alg parameter in JWE).
	/// These algorithms are used to encrypt the Content Encryption Key (CEK).
	/// </summary>
	public static class KeyManagement
	{
		/// <summary>
		/// RSA-PKCS1-v1_5 key encryption algorithm.
		/// This algorithm uses RSAES-PKCS1-v1_5 for key encryption.
		/// Note: RSA1_5 is deprecated in favor of RSA-OAEP due to security concerns.
		/// </summary>
		public const string Rsa1_5 = "RSA1_5";

		/// <summary>
		/// RSA-OAEP key encryption algorithm with default parameters.
		/// This algorithm uses RSAES OAEP with SHA-1 and MGF1 with SHA-1.
		/// Recommended for most RSA-based key encryption scenarios.
		/// </summary>
		public const string RsaOaep = "RSA-OAEP";

		/// <summary>
		/// RSA-OAEP key encryption algorithm with SHA-256.
		/// This algorithm uses RSAES OAEP with SHA-256 and MGF1 with SHA-256.
		/// Provides enhanced security compared to RSA-OAEP with SHA-1.
		/// </summary>
		public const string RsaOaep256 = "RSA-OAEP-256";

		/// <summary>
		/// AES Key Wrap with 128-bit key.
		/// This algorithm uses the AES Key Wrap algorithm (RFC 3394) with a 128-bit key.
		/// </summary>
		public const string Aes128KW = "A128KW";

		/// <summary>
		/// AES Key Wrap with 192-bit key.
		/// This algorithm uses the AES Key Wrap algorithm (RFC 3394) with a 192-bit key.
		/// </summary>
		public const string Aes192KW = "A192KW";

		/// <summary>
		/// AES Key Wrap with 256-bit key.
		/// This algorithm uses the AES Key Wrap algorithm (RFC 3394) with a 256-bit key.
		/// </summary>
		public const string Aes256KW = "A256KW";

		/// <summary>
		/// Direct use of a shared symmetric key as the Content Encryption Key (CEK).
		/// No key wrapping is performed; the symmetric key is used directly for content encryption.
		/// </summary>
		public const string Dir = "dir";

		/// <summary>
		/// Elliptic Curve Diffie-Hellman Ephemeral Static key agreement.
		/// This algorithm uses ECDH-ES to establish a shared secret for key encryption.
		/// </summary>
		public const string EcdhEs = "ECDH-ES";

		/// <summary>
		/// ECDH-ES with AES Key Wrap using 128-bit key.
		/// Combines ECDH-ES key agreement with AES-128 Key Wrap.
		/// </summary>
		public const string EcdhEsAes128KW = "ECDH-ES+A128KW";

		/// <summary>
		/// ECDH-ES with AES Key Wrap using 192-bit key.
		/// Combines ECDH-ES key agreement with AES-192 Key Wrap.
		/// </summary>
		public const string EcdhEsAes192KW = "ECDH-ES+A192KW";

		/// <summary>
		/// ECDH-ES with AES Key Wrap using 256-bit key.
		/// Combines ECDH-ES key agreement with AES-256 Key Wrap.
		/// </summary>
		public const string EcdhEsAes256KW = "ECDH-ES+A256KW";

		/// <summary>
		/// AES GCM Key Wrap with 128-bit key.
		/// This algorithm uses AES GCM for key wrapping with a 128-bit key.
		/// </summary>
		public const string Aes128Gcmkw = "A128GCMKW";

		/// <summary>
		/// AES GCM Key Wrap with 192-bit key.
		/// This algorithm uses AES GCM for key wrapping with a 192-bit key.
		/// </summary>
		public const string Aes192Gcmkw = "A192GCMKW";

		/// <summary>
		/// AES GCM Key Wrap with 256-bit key.
		/// This algorithm uses AES GCM for key wrapping with a 256-bit key.
		/// </summary>
		public const string Aes256Gcmkw = "A256GCMKW";

		/// <summary>
		/// PBES2 with HMAC SHA-256 and AES Key Wrap with 128-bit key.
		/// Password-Based Encryption Scheme 2 using HMAC SHA-256 and AES-128 Key Wrap.
		/// </summary>
		public const string Pbes2HmacSha256Aes128KW = "PBES2-HS256+A128KW";

		/// <summary>
		/// PBES2 with HMAC SHA-384 and AES Key Wrap with 192-bit key.
		/// Password-Based Encryption Scheme 2 using HMAC SHA-384 and AES-192 Key Wrap.
		/// </summary>
		public const string Pbes2HmacSha384Aes192KW = "PBES2-HS384+A192KW";

		/// <summary>
		/// PBES2 with HMAC SHA-512 and AES Key Wrap with 256-bit key.
		/// Password-Based Encryption Scheme 2 using HMAC SHA-512 and AES-256 Key Wrap.
		/// </summary>
		public const string Pbes2HmacSha512Aes256KW = "PBES2-HS512+A256KW";
	}

	/// <summary>
	/// Content Encryption Algorithms (enc parameter in JWE).
	/// These algorithms are used to encrypt the actual content/payload.
	/// </summary>
	public static class ContentEncryption
	{
		/// <summary>
		/// AES_128_CBC_HMAC_SHA_256 authenticated encryption algorithm.
		/// This algorithm uses AES-128 in CBC mode with HMAC SHA-256 for authentication.
		/// Combines AES-CBC-128 encryption with HMAC-SHA-256 authentication.
		/// </summary>
		public const string Aes128CbcHmacSha256 = "A128CBC-HS256";

		/// <summary>
		/// AES_192_CBC_HMAC_SHA_384 authenticated encryption algorithm.
		/// This algorithm uses AES-192 in CBC mode with HMAC SHA-384 for authentication.
		/// Combines AES-CBC-192 encryption with HMAC-SHA-384 authentication.
		/// </summary>
		public const string Aes192CbcHmacSha384 = "A192CBC-HS384";

		/// <summary>
		/// AES_256_CBC_HMAC_SHA_512 authenticated encryption algorithm.
		/// This algorithm uses AES-256 in CBC mode with HMAC SHA-512 for authentication.
		/// Combines AES-CBC-256 encryption with HMAC-SHA-512 authentication.
		/// </summary>
		public const string Aes256CbcHmacSha512 = "A256CBC-HS512";

		/// <summary>
		/// AES GCM with 128-bit key.
		/// This algorithm uses AES in Galois/Counter Mode (GCM) with a 128-bit key.
		/// Provides both encryption and authentication in a single operation.
		/// Recommended for modern applications due to performance and security.
		/// </summary>
		public const string Aes128Gcm = "A128GCM";

		/// <summary>
		/// AES GCM with 192-bit key.
		/// This algorithm uses AES in Galois/Counter Mode (GCM) with a 192-bit key.
		/// Provides both encryption and authentication in a single operation.
		/// </summary>
		public const string Aes192Gcm = "A192GCM";

		/// <summary>
		/// AES GCM with 256-bit key.
		/// This algorithm uses AES in Galois/Counter Mode (GCM) with a 256-bit key.
		/// Provides both encryption and authentication in a single operation.
		/// Offers the highest security level among AES GCM variants.
		/// </summary>
		public const string Aes256Gcm = "A256GCM";
	}
}
