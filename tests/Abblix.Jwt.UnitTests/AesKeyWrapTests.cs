// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt.Encryption;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Tests for the RFC 3394 AES Key Wrap implementation: the six known-answer vectors of RFC 3394 §4
/// pin the wrap construction byte-exact, tamper tests prove the integrity check register rejects
/// every single-byte forgery, and JWE round-trips cover A128KW/A192KW/A256KW end to end.
/// </summary>
public class AesKeyWrapTests
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
	/// The 128-bit KEK of the RFC 3394 §4.1 vector, shared with the negative tests below.
	/// </summary>
	private const string KeyEncryptionKey128Hex = "000102030405060708090A0B0C0D0E0F";

	/// <summary>
	/// The six complete known-answer vectors of RFC 3394 §4.1-§4.6, covering every
	/// KEK-size × key-data-size combination the specification defines.
	/// </summary>
	public static TheoryData<string, string, string> Rfc3394Vectors => new()
	{
		// §4.1: 128 bits of Key Data with a 128-bit KEK
		{
			KeyEncryptionKey128Hex,
			"00112233445566778899AABBCCDDEEFF",
			"1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5"
		},
		// §4.2: 128 bits of Key Data with a 192-bit KEK
		{
			"000102030405060708090A0B0C0D0E0F1011121314151617",
			"00112233445566778899AABBCCDDEEFF",
			"96778B25AE6CA435F92B5B97C050AED2468AB8A17AD84E5D"
		},
		// §4.3: 128 bits of Key Data with a 256-bit KEK
		{
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF",
			"64E8C3F9CE0F5BA263E9777905818A2A93C8191E7D6E8AE7"
		},
		// §4.4: 192 bits of Key Data with a 192-bit KEK
		{
			"000102030405060708090A0B0C0D0E0F1011121314151617",
			"00112233445566778899AABBCCDDEEFF0001020304050607",
			"031D33264E15D33268F24EC260743EDCE1C6C7DDEE725A936BA814915C6762D2"
		},
		// §4.5: 192 bits of Key Data with a 256-bit KEK
		{
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF0001020304050607",
			"A8F9BC1612C68B3FF6E6F4FBE30E71E4769C8B80A32CB8958CD5D17D6B254DA1"
		},
		// §4.6: 256 bits of Key Data with a 256-bit KEK
		{
			"000102030405060708090A0B0C0D0E0F101112131415161718191A1B1C1D1E1F",
			"00112233445566778899AABBCCDDEEFF000102030405060708090A0B0C0D0E0F",
			"28C9F404C4B810F4CBCCB35CFB87F8263F5786E2D80ED326CBC7F0E71A99F43BFB988B9B7A02DD21"
		},
	};

	[Theory]
	[MemberData(nameof(Rfc3394Vectors))]
	public void Wrap_Rfc3394KnownAnswerVectors_ProducesExpectedCiphertext(string keyEncryptionKeyHex, string keyHex, string expectedHex)
	{
		var wrapped = AesKeyWrap.Wrap(Convert.FromHexString(keyEncryptionKeyHex), Convert.FromHexString(keyHex));

		Assert.Equal(Convert.FromHexString(expectedHex), wrapped);
	}

	[Theory]
	[MemberData(nameof(Rfc3394Vectors))]
	public void TryUnwrap_Rfc3394KnownAnswerVectors_RecoversKeyData(string keyEncryptionKeyHex, string keyHex, string wrappedHex)
	{
		Assert.True(AesKeyWrap.TryUnwrap(Convert.FromHexString(keyEncryptionKeyHex), Convert.FromHexString(wrappedHex), out var keyData));
		Assert.Equal(Convert.FromHexString(keyHex), keyData);
	}

	/// <summary>
	/// RFC 3394 §2.2.2: the integrity check register comparison is the sole integrity mechanism of the
	/// construction, so flipping ANY single byte of the wrapped key must make unwrapping fail -
	/// every byte position is exercised, not a sample.
	/// </summary>
	[Fact]
	public void TryUnwrap_AnySingleByteTampered_Fails()
	{
		var keyEncryptionKey = Convert.FromHexString(KeyEncryptionKey128Hex);
		var wrapped = Convert.FromHexString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");

		for (var position = 0; position < wrapped.Length; position++)
		{
			var tampered = (byte[])wrapped.Clone();
			tampered[position] ^= 0x01;

			Assert.False(
				AesKeyWrap.TryUnwrap(keyEncryptionKey, tampered, out var keyData),
				$"Unwrap must fail when byte {position} is tampered");
			Assert.Null(keyData);
		}
	}

	[Fact]
	public void TryUnwrap_WrongKek_Fails()
	{
		var wrongKeyEncryptionKey = Convert.FromHexString("0F0E0D0C0B0A09080706050403020100");
		var wrapped = Convert.FromHexString("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5");

		Assert.False(AesKeyWrap.TryUnwrap(wrongKeyEncryptionKey, wrapped, out var keyData));
		Assert.Null(keyData);
	}

	[Theory]
	[InlineData(0)]  // empty
	[InlineData(16)] // two semiblocks only - a valid wrap is at least three
	[InlineData(23)] // not a multiple of 8
	[InlineData(25)] // not a multiple of 8
	public void TryUnwrap_InvalidWrappedKeyLength_Fails(int length)
	{
		var keyEncryptionKey = Convert.FromHexString(KeyEncryptionKey128Hex);

		Assert.False(AesKeyWrap.TryUnwrap(keyEncryptionKey, new byte[length], out var keyData));
		Assert.Null(keyData);
	}

	[Theory]
	[InlineData(8)]  // single semiblock - below the NIST SP 800-38F two-semiblock minimum
	[InlineData(15)] // not a multiple of 8
	[InlineData(20)] // not a multiple of 8
	public void Wrap_InvalidKeyDataLength_Throws(int length)
	{
		var keyEncryptionKey = Convert.FromHexString(KeyEncryptionKey128Hex);

		Assert.Throws<ArgumentException>(() => AesKeyWrap.Wrap(keyEncryptionKey, new byte[length]));
	}

	/// <summary>
	/// Full JWE round-trips for every AES Key Wrap size × every content encryption algorithm.
	/// Verifies RFC 7518 Section 4.4 through the complete encrypt → decrypt pipeline.
	/// </summary>
	[Theory]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes128KW, 16, EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes128KW, 16, EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes128KW, 16, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes128KW, 16, EncryptionAlgorithms.ContentEncryption.Aes128Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes128KW, 16, EncryptionAlgorithms.ContentEncryption.Aes192Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes128KW, 16, EncryptionAlgorithms.ContentEncryption.Aes256Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes192KW, 24, EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes192KW, 24, EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes192KW, 24, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes192KW, 24, EncryptionAlgorithms.ContentEncryption.Aes128Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes192KW, 24, EncryptionAlgorithms.ContentEncryption.Aes192Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes192KW, 24, EncryptionAlgorithms.ContentEncryption.Aes256Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes256KW, 32, EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes256KW, 32, EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes256KW, 32, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes256KW, 32, EncryptionAlgorithms.ContentEncryption.Aes128Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes256KW, 32, EncryptionAlgorithms.ContentEncryption.Aes192Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes256KW, 32, EncryptionAlgorithms.ContentEncryption.Aes256Gcm)]
	public async Task AesKeyWrap_JweRoundTrip_AllContentEncryptionAlgorithms_Success(
		string keyManagementAlgorithm,
		int keyEncryptionKeySize,
		string contentEncryption)
	{
		// Arrange
		var keyEncryptionKey = new OctetJsonWebKey
		{
			KeyId = $"test-kw-{keyEncryptionKeySize * 8}",
			Algorithm = keyManagementAlgorithm,
			KeyValue = CryptoRandom.GetRandomBytes(keyEncryptionKeySize),
		};
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
		var token = CreateTestToken();

		// Act: Encrypt
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwe = await creator.IssueAsync(token, signingKey, keyEncryptionKey, keyManagementAlgorithm, contentEncryption);

		// Assert: JWE compact serialization with a non-empty encrypted_key (CEK + 8-byte register)
		var parts = jwe.Split('.');
		Assert.Equal(5, parts.Length);
		Assert.NotEmpty(parts[1]);

		// Act: Decrypt and validate
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var result = await validator.ValidateAsync(jwe, new ValidationParameters
		{
			ValidateAudience = aud => Task.FromResult(aud.Contains("test-audience")),
			ValidateIssuer = iss => Task.FromResult(iss == "test-issuer"),
			ResolveTokenDecryptionKeys = _ => keyEncryptionKey.ToAsync(),
			ResolveIssuerSigningKeys = _ => signingKey.ToAsync(),
		});

		// Assert: claims round-tripped
		Assert.True(result.TryGetSuccess(out var decrypted));
		Assert.Equal(token.Payload.JwtId, decrypted.Payload.JwtId);
		Assert.Equal("test-value", decrypted.Payload.Json["test-claim"]?.GetValue<string>());
	}

	/// <summary>
	/// Per RFC 7518 Section 4.4 the KEK size must match the algorithm name exactly -
	/// a wrong-family key must be rejected, not silently truncated or padded.
	/// </summary>
	[Fact]
	public async Task AesKeyWrap_WrongKekSize_ThrowsException()
	{
		var wrongSizeKeyEncryptionKey = new OctetJsonWebKey
		{
			KeyId = "wrong-size",
			Algorithm = EncryptionAlgorithms.KeyManagement.Aes128KW,
			KeyValue = CryptoRandom.GetRandomBytes(32), // Wrong: A128KW requires 16 bytes
		};
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		await Assert.ThrowsAsync<InvalidOperationException>(() => creator.IssueAsync(
			CreateTestToken(),
			signingKey,
			wrongSizeKeyEncryptionKey,
			EncryptionAlgorithms.KeyManagement.Aes128KW,
			EncryptionAlgorithms.ContentEncryption.Aes256Gcm));
	}

	private static JsonWebToken CreateTestToken()
	{
		var issuedAt = TimeProvider.System.GetUtcNow();

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
}
