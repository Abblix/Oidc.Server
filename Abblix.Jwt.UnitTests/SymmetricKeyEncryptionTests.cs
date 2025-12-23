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

using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Unit tests for symmetric key encryption algorithms in JWE (JSON Web Encryption).
/// Tests AES-GCM Key Wrap (A128GCMKW, A192GCMKW, A256GCMKW) and Direct Key Agreement (dir).
/// Verifies RFC 7518 Section 4.5 (Direct Encryption) and Section 4.7 (AES-GCM Key Wrap).
/// </summary>
public class SymmetricKeyEncryptionTests
{
	private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

	private static IServiceProvider CreateServiceProvider()
	{
		var services = new ServiceCollection();
		services.AddSingleton(TimeProvider.System);
		services.AddLogging();
		services.AddJsonWebTokens();
		return services.BuildServiceProvider();
	}

	/// <summary>
	/// Tests A128GCMKW (AES-128 GCM Key Wrap) with all content encryption algorithms.
	/// Verifies RFC 7518 Section 4.7.1 using 128-bit key encryption key.
	/// </summary>
	[Theory]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes128Gcm)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes192Gcm)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes256Gcm)]
	public async Task A128GCMKW_EncryptDecrypt_AllContentEncryptionAlgorithms_Success(string contentEncryption)
	{
		// Arrange: Create 128-bit symmetric key for A128GCMKW
		var encryptionKey = new OctetJsonWebKey
		{
			KeyId = "test-key-128",
			Algorithm = EncryptionAlgorithms.KeyManagement.Aes128Gcmkw,
			KeyValue = CryptoRandom.GetRandomBytes(16), // 128 bits
		};

		await TestSymmetricEncryption(
			EncryptionAlgorithms.KeyManagement.Aes128Gcmkw,
			contentEncryption,
			encryptionKey);
	}

	/// <summary>
	/// Tests A192GCMKW (AES-192 GCM Key Wrap) with all content encryption algorithms.
	/// Verifies RFC 7518 Section 4.7.1 using 192-bit key encryption key.
	/// </summary>
	[Theory]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes128Gcm)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes192Gcm)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes256Gcm)]
	public async Task A192GCMKW_EncryptDecrypt_AllContentEncryptionAlgorithms_Success(string contentEncryption)
	{
		// Arrange: Create 192-bit symmetric key for A192GCMKW
		var encryptionKey = new OctetJsonWebKey
		{
			KeyId = "test-key-192",
			Algorithm = EncryptionAlgorithms.KeyManagement.Aes192Gcmkw,
			KeyValue = CryptoRandom.GetRandomBytes(24), // 192 bits
		};

		await TestSymmetricEncryption(
			EncryptionAlgorithms.KeyManagement.Aes192Gcmkw,
			contentEncryption,
			encryptionKey);
	}

	/// <summary>
	/// Tests A256GCMKW (AES-256 GCM Key Wrap) with all content encryption algorithms.
	/// Verifies RFC 7518 Section 4.7.1 using 256-bit key encryption key.
	/// </summary>
	[Theory]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes128Gcm)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes192Gcm)]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes256Gcm)]
	public async Task A256GCMKW_EncryptDecrypt_AllContentEncryptionAlgorithms_Success(string contentEncryption)
	{
		// Arrange: Create 256-bit symmetric key for A256GCMKW
		var encryptionKey = new OctetJsonWebKey
		{
			KeyId = "test-key-256",
			Algorithm = EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
			KeyValue = CryptoRandom.GetRandomBytes(32), // 256 bits
		};

		await TestSymmetricEncryption(
			EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
			contentEncryption,
			encryptionKey);
	}

	/// <summary>
	/// Tests "dir" (Direct Key Agreement) with all content encryption algorithms.
	/// Verifies RFC 7518 Section 4.5 - the shared symmetric key is used directly as the CEK.
	/// </summary>
	[Theory]
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256, 32)] // 256 bits (128 AES + 128 HMAC)
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384, 48)] // 384 bits (192 AES + 192 HMAC)
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512, 64)] // 512 bits (256 AES + 256 HMAC)
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes128Gcm, 16)]           // 128 bits
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes192Gcm, 24)]           // 192 bits
	[InlineData(EncryptionAlgorithms.ContentEncryption.Aes256Gcm, 32)]           // 256 bits
	public async Task DirectKeyAgreement_EncryptDecrypt_AllContentEncryptionAlgorithms_Success(
		string contentEncryption,
		int keySize)
	{
		// Arrange: Create shared symmetric key matching the content encryption algorithm's required key size
		// Per RFC 7518 Section 4.5: "the symmetric key value MUST be the same as the CEK"
		var sharedKey = new OctetJsonWebKey
		{
			KeyId = "shared-key",
			Algorithm = EncryptionAlgorithms.KeyManagement.Dir,
			KeyValue = CryptoRandom.GetRandomBytes(keySize),
		};

		await TestSymmetricEncryption(
			EncryptionAlgorithms.KeyManagement.Dir,
			contentEncryption,
			sharedKey);
	}

	/// <summary>
	/// Tests that A128GCMKW rejects keys of incorrect size.
	/// Per RFC 7518 Section 4.7: A128GCMKW requires exactly 128-bit (16-byte) key.
	/// </summary>
	[Fact]
	public async Task A128GCMKW_WrongKeySize_ThrowsException()
	{
		// Arrange: Create key with wrong size (256-bit instead of 128-bit)
		var wrongSizeKey = new OctetJsonWebKey
		{
			KeyId = "wrong-size",
			Algorithm = EncryptionAlgorithms.KeyManagement.Aes128Gcmkw,
			KeyValue = CryptoRandom.GetRandomBytes(32), // Wrong: should be 16 bytes
		};

		// Act & Assert
		await Assert.ThrowsAsync<InvalidOperationException>(() =>
			TestSymmetricEncryption(
				EncryptionAlgorithms.KeyManagement.Aes128Gcmkw,
				EncryptionAlgorithms.ContentEncryption.Aes128Gcm,
				wrongSizeKey));
	}

	/// <summary>
	/// Tests that A256GCMKW rejects keys of incorrect size.
	/// Per RFC 7518 Section 4.7: A256GCMKW requires exactly 256-bit (32-byte) key.
	/// </summary>
	[Fact]
	public async Task A256GCMKW_WrongKeySize_ThrowsException()
	{
		// Arrange: Create key with wrong size (128-bit instead of 256-bit)
		var wrongSizeKey = new OctetJsonWebKey
		{
			KeyId = "wrong-size",
			Algorithm = EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
			KeyValue = CryptoRandom.GetRandomBytes(16), // Wrong: should be 32 bytes
		};

		// Act & Assert
		await Assert.ThrowsAsync<InvalidOperationException>(() =>
			TestSymmetricEncryption(
				EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
				EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
				wrongSizeKey));
	}

	/// <summary>
	/// Tests that Direct Key Agreement requires the shared key to match the CEK size.
	/// Per RFC 7518 Section 4.5: "the symmetric key value MUST be the same as the CEK".
	/// </summary>
	[Fact]
	public async Task DirectKeyAgreement_WrongKeySize_ThrowsException()
	{
		// Arrange: Create key with wrong size for A256GCM (needs 32 bytes, providing 16)
		var wrongSizeKey = new OctetJsonWebKey
		{
			KeyId = "wrong-size",
			Algorithm = EncryptionAlgorithms.KeyManagement.Dir,
			KeyValue = CryptoRandom.GetRandomBytes(16), // Wrong: A256GCM needs 32 bytes
		};

		// Act & Assert
		await Assert.ThrowsAsync<ArgumentException>(() =>
			TestSymmetricEncryption(
				EncryptionAlgorithms.KeyManagement.Dir,
				EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
				wrongSizeKey));
	}

	/// <summary>
	/// Tests that AES-GCM Key Wrap generates unique encrypted keys for each encryption.
	/// Per RFC 7518 Section 4.7.1.1: "a new random 96-bit Initialization Vector MUST be generated".
	/// </summary>
	[Fact]
	public async Task AesGcmKeyWrap_MultipleEncryptions_ProducesDifferentCiphertext()
	{
		// Arrange
		var encryptionKey = new OctetJsonWebKey
		{
			KeyId = "test-key",
			Algorithm = EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
			KeyValue = CryptoRandom.GetRandomBytes(32),
		};

		var signingKey = JsonWebKeyFactory.CreateRsa(JsonWebKeyUseNames.Sig);
		var token = CreateTestToken();

		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();

		// Act: Encrypt the same token twice
		var jwe1 = await creator.IssueAsync(
			token,
			signingKey,
			encryptionKey,
			EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
			EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

		var jwe2 = await creator.IssueAsync(
			token,
			signingKey,
			encryptionKey,
			EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
			EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

		// Assert: JWE tokens should be different due to random IV
		Assert.NotEqual(jwe1, jwe2);

		// But both should decrypt to the same plaintext
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var parameters = CreateValidationParameters(encryptionKey, signingKey);

		var result1 = await validator.ValidateAsync(jwe1, parameters);
		var result2 = await validator.ValidateAsync(jwe2, parameters);

		Assert.True(result1.TryGetSuccess(out var jwt1));
		Assert.True(result2.TryGetSuccess(out var jwt2));

		Assert.Equal(jwt1.Payload.JwtId, jwt2.Payload.JwtId);
	}

	/// <summary>
	/// Tests that Direct Key Agreement produces empty encrypted_key field.
	/// Per RFC 7518 Section 4.5: "The JWE Encrypted Key value is the empty octet sequence."
	/// </summary>
	[Fact]
	public async Task DirectKeyAgreement_EncryptedKeyField_IsEmpty()
	{
		// Arrange
		var sharedKey = new OctetJsonWebKey
		{
			KeyId = "shared-key",
			Algorithm = EncryptionAlgorithms.KeyManagement.Dir,
			KeyValue = CryptoRandom.GetRandomBytes(32), // 256 bits for A256GCM
		};

		var signingKey = JsonWebKeyFactory.CreateRsa(JsonWebKeyUseNames.Sig);
		var token = CreateTestToken();

		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();

		// Act
		var jwe = await creator.IssueAsync(
			token,
			signingKey,
			sharedKey,
			EncryptionAlgorithms.KeyManagement.Dir,
			EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

		// Assert: The second part (encrypted_key) should be empty
		var parts = jwe.Split('.');
		Assert.Equal(5, parts.Length); // JWE compact serialization has 5 parts
		Assert.Empty(parts[1]); // encrypted_key should be empty for "dir"
	}

	/// <summary>
	/// Tests that decryption fails with wrong key.
	/// Verifies that authenticated encryption detects key mismatch.
	/// </summary>
	[Fact]
	public async Task AesGcmKeyWrap_WrongDecryptionKey_DecryptionFails()
	{
		// Arrange: Encrypt with one key
		var encryptionKey = new OctetJsonWebKey
		{
			KeyId = "key-1",
			Algorithm = EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
			KeyValue = CryptoRandom.GetRandomBytes(32),
		};

		var signingKey = JsonWebKeyFactory.CreateRsa(JsonWebKeyUseNames.Sig);
		var token = CreateTestToken();

		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwe = await creator.IssueAsync(
			token,
			signingKey,
			encryptionKey,
			EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
			EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

		// Act: Try to decrypt with different key
		var wrongKey = new OctetJsonWebKey
		{
			KeyId = "key-2",
			Algorithm = EncryptionAlgorithms.KeyManagement.Aes256Gcmkw,
			KeyValue = CryptoRandom.GetRandomBytes(32), // Different random key
		};

		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var parameters = CreateValidationParameters(wrongKey, signingKey);

		var result = await validator.ValidateAsync(jwe, parameters);

		// Assert: Decryption should fail
		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidToken, error.Error);
		// The error message could be either "Failed to decrypt JWE" or "No decryption keys found"
		// depending on whether the wrong key matches by KeyId
		Assert.True(
			error.ErrorDescription.Contains("Failed to decrypt JWE") ||
			error.ErrorDescription.Contains("No decryption keys found"),
			$"Expected decryption failure message, but got: {error.ErrorDescription}");
	}

	/// <summary>
	/// Common test helper for symmetric key encryption algorithms.
	/// Tests the complete encrypt → decrypt cycle with claim validation.
	/// </summary>
	private static async Task TestSymmetricEncryption(
		string keyManagementAlgorithm,
		string contentEncryption,
		OctetJsonWebKey encryptionKey)
	{
		// Arrange
		var signingKey = JsonWebKeyFactory.CreateRsa(JsonWebKeyUseNames.Sig);
		var token = CreateTestToken();

		// Act: Encrypt
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwe = await creator.IssueAsync(token, signingKey, encryptionKey, keyManagementAlgorithm, contentEncryption);

		// Assert: JWE should be created
		Assert.NotNull(jwe);
		Assert.NotEmpty(jwe);

		// Verify JWE structure (5 parts: header.encryptedKey.iv.ciphertext.authTag)
		var parts = jwe.Split('.');
		Assert.Equal(5, parts.Length);

		// Act: Decrypt and validate
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var parameters = CreateValidationParameters(encryptionKey, signingKey);

		var validationResult = await validator.ValidateAsync(jwe, parameters);

		// Assert: Validation should succeed
		Assert.True(validationResult.TryGetSuccess(out var result));
		Assert.NotNull(result);

		// Verify claims round-tripped correctly
		Assert.Equal(token.Payload.JwtId, result.Payload.JwtId);
		Assert.Equal(token.Payload.Issuer, result.Payload.Issuer);
		Assert.Equal(token.Payload.Audiences, result.Payload.Audiences);
		Assert.Equal("test-value", result.Payload.Json["test-claim"]?.GetValue<string>());
	}

	/// <summary>
	/// Creates a test JWT with common claims for testing.
	/// </summary>
	private static JsonWebToken CreateTestToken()
	{
		var issuedAt = DateTimeOffset.UtcNow;

		return new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.RS256 },
			Payload =
			{
				JwtId = Guid.NewGuid().ToString("N"),
				IssuedAt = issuedAt,
				NotBefore = issuedAt,
				ExpiresAt = issuedAt + TimeSpan.FromMinutes(10),
				Issuer = "test-issuer",
				Audiences = ["test-audience"],
				["test-claim"] = "test-value",
			},
		};
	}

	/// <summary>
	/// Creates validation parameters for JWT validation.
	/// </summary>
	private static ValidationParameters CreateValidationParameters(
		OctetJsonWebKey encryptionKey,
		JsonWebKey signingKey)
	{
		return new ValidationParameters
		{
			ValidateAudience = aud => Task.FromResult(aud.Contains("test-audience")),
			ValidateIssuer = iss => Task.FromResult(iss == "test-issuer"),
			ResolveTokenDecryptionKeys = _ => new[] { encryptionKey }.ToAsyncEnumerable(),
			ResolveIssuerSigningKeys = _ => new[] { signingKey }.ToAsyncEnumerable(),
		};
	}
}
