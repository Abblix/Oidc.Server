// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Tests for PBES2 password-based key encryption (RFC 7518 Section 4.8). The complete worked
/// example of RFC 7517 Appendix C pins the PBKDF2 salt construction and the RFC 3394 wrap
/// byte-exact; the negative tests exercise the inbound 'p2s'/'p2c' validation, including the
/// denial-of-service cap on the attacker-controlled iteration count.
/// </summary>
public class Pbes2KeyEncryptionTests
{
	private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

	private static IServiceProvider CreateServiceProvider()
	{
		var services = new ServiceCollection();
		services.AddSingleton(TimeProvider.System);
		services.AddLogging();
		// PBES2 is deliberately not part of the AddJsonWebTokens defaults - a host opts in explicitly
		services.AddPbes2KeyManagement();
		services.AddJsonWebTokens();
		return services.BuildServiceProvider();
	}

	/// <summary>
	/// The passphrase of RFC 7517 Appendix C.2, carried as an octet key per this library's contract.
	/// </summary>
	private static OctetJsonWebKey CreateAppendixCPasswordKey() => new()
	{
		KeyId = "pbes2-password",
		KeyValue = Encoding.UTF8.GetBytes("Thus from my lips, by yours, my sin is purged."),
	};

	/// <summary>
	/// The protected header of RFC 7517 Appendix C.3.
	/// </summary>
	private static JsonWebTokenHeader CreateAppendixCHeader() => new(new JsonObject
	{
		[JwtClaimTypes.Algorithm] = EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW,
		[JwtClaimTypes.Pbes2SaltInput] = "2WCTcJZ1Rvd_CJuJripQ1w",
		[JwtClaimTypes.Pbes2IterationCount] = 4096,
		[JwtClaimTypes.EncryptionAlgorithm] = EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256,
		[JwtClaimTypes.ContentType] = "jwk+json",
	});

	/// <summary>
	/// The Content Encryption Key of RFC 7517 Appendix C.4.
	/// </summary>
	private static readonly byte[] AppendixCContentEncryptionKey =
	[
		111, 27, 25, 52, 66, 29, 20, 78, 92, 176, 56, 240, 65, 208, 82, 112,
		161, 131, 36, 55, 202, 236, 185, 172, 129, 23, 153, 194, 195, 48, 253, 182,
	];

	// The JWE Encrypted Key of RFC 7517 Appendix C.5.
	private const string AppendixCEncryptedKey = "TrqXOwuNUfDV9VPTNbyGvEJ9JMjefAVn-TR1uIxR9p6hsRQh9Tk7BA";

	/// <summary>
	/// RFC 7517 Appendix C, the canonical worked PBES2 example: deriving the KEK from the
	/// passphrase with the listed 'p2s'/'p2c' and unwrapping the listed JWE Encrypted Key must
	/// recover exactly the CEK the appendix lists. This known-answer test pins the PBKDF2 salt
	/// construction (UTF8(alg) || 0x00 || p2s), the PRF choice and the RFC 3394 unwrap together.
	/// </summary>
	[Fact]
	public void TryDecryptKey_Rfc7517AppendixC_RecoversExpectedCek()
	{
		var encryptor = new Pbes2KeyEncryptor(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW);

		var succeeded = encryptor.TryDecryptKey(
			CreateAppendixCHeader(),
			CreateAppendixCPasswordKey(),
			Base64Url.DecodeFromChars(AppendixCEncryptedKey),
			out var contentEncryptionKey);

		Assert.True(succeeded);
		Assert.Equal(AppendixCContentEncryptionKey, contentEncryptionKey);
	}

	[Fact]
	public void TryDecryptKey_WrongPassword_Fails()
	{
		var wrongPassword = new OctetJsonWebKey
		{
			KeyId = "wrong",
			KeyValue = Encoding.UTF8.GetBytes("Deny thy father and refuse thy name."),
		};

		var encryptor = new Pbes2KeyEncryptor(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW);

		Assert.False(encryptor.TryDecryptKey(
			CreateAppendixCHeader(), wrongPassword, Base64Url.DecodeFromChars(AppendixCEncryptedKey), out _));
	}

	[Fact]
	public void TryDecryptKey_TamperedEncryptedKey_Fails()
	{
		var encryptedKey = Base64Url.DecodeFromChars(AppendixCEncryptedKey);
		encryptedKey[0] ^= 0x01;

		var encryptor = new Pbes2KeyEncryptor(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW);

		Assert.False(encryptor.TryDecryptKey(
			CreateAppendixCHeader(), CreateAppendixCPasswordKey(), encryptedKey, out _));
	}

	/// <summary>
	/// The 'p2c' iteration count is attacker-controlled on inbound tokens. Values above the hard
	/// cap must be rejected before any PBKDF2 work - otherwise a single crafted token demands an
	/// arbitrary amount of computation (the CVE-2022-36083 class of denial of service; the cap of
	/// 10,000 is the remediation consensus across JOSE implementations). Values below the
	/// RFC 7518 section 4.8.1.2 recommended minimum signal a downgrade and are rejected as well.
	/// </summary>
	[Theory]
	[InlineData(10_001)]        // above the DoS cap
	[InlineData(int.MaxValue)]  // pathological
	[InlineData(999)]           // below the spec minimum
	[InlineData(0)]
	[InlineData(-1)]
	public void TryDecryptKey_IterationCountOutOfBounds_Fails(int iterationCount)
	{
		var header = CreateAppendixCHeader();
		header.Pbes2IterationCount = iterationCount;

		var encryptor = new Pbes2KeyEncryptor(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW);

		Assert.False(encryptor.TryDecryptKey(
			header, CreateAppendixCPasswordKey(), Base64Url.DecodeFromChars(AppendixCEncryptedKey), out _));
	}

	/// <summary>
	/// RFC 7518 section 4.8.1.1: the 'p2s' salt input must be at least 8 octets.
	/// </summary>
	[Fact]
	public void TryDecryptKey_SaltInputTooShort_Fails()
	{
		var header = CreateAppendixCHeader();
		header.Pbes2SaltInput = Base64Url.EncodeToString(CryptoRandom.GetRandomBytes(7));

		var encryptor = new Pbes2KeyEncryptor(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW);

		Assert.False(encryptor.TryDecryptKey(
			header, CreateAppendixCPasswordKey(), Base64Url.DecodeFromChars(AppendixCEncryptedKey), out _));
	}

	[Theory]
	[InlineData(JwtClaimTypes.Pbes2SaltInput)]
	[InlineData(JwtClaimTypes.Pbes2IterationCount)]
	public void TryDecryptKey_MissingPbes2HeaderParameter_Fails(string missingParameter)
	{
		var header = CreateAppendixCHeader();
		header.Json.Remove(missingParameter);

		var encryptor = new Pbes2KeyEncryptor(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW);

		Assert.False(encryptor.TryDecryptKey(
			header, CreateAppendixCPasswordKey(), Base64Url.DecodeFromChars(AppendixCEncryptedKey), out _));
	}

	/// <summary>
	/// The encryption side must generate a fresh salt input of comfortable size and record both
	/// PBKDF2 inputs in the header, so any conformant recipient (this library included) can
	/// re-derive the KEK.
	/// </summary>
	[Fact]
	public void EncryptKey_EmitsSaltAndIterationCountHeaders_AndRoundTrips()
	{
		var passwordKey = CreateAppendixCPasswordKey();
		var header = new JsonWebTokenHeader(new JsonObject())
		{
			Algorithm = EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW,
			EncryptionAlgorithm = EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
		};
		var contentEncryptionKey = CryptoRandom.GetRandomBytes(32);

		var encryptor = new Pbes2KeyEncryptor(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW);

		var encryptedKey = encryptor.EncryptKey(header, passwordKey, contentEncryptionKey);

		Assert.NotNull(header.Pbes2SaltInput);
		Assert.True(Base64Url.DecodeFromChars(header.Pbes2SaltInput).Length >= 8);

		// The outbound default must pass this library's own inbound bounds - and stay under the
		// post-advisory inbound caps of the wider JOSE ecosystem, so produced tokens decrypt anywhere.
		Assert.NotNull(header.Pbes2IterationCount);
		Assert.InRange(header.Pbes2IterationCount.Value, 1000, 10_000);

		Assert.True(encryptor.TryDecryptKey(header, passwordKey, encryptedKey, out var recoveredKey));
		Assert.Equal(contentEncryptionKey, recoveredKey);
	}

	/// <summary>
	/// Full JWE round-trips through the complete encrypt → decrypt pipeline for every PBES2 variant.
	/// </summary>
	[Theory]
	[InlineData(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW, EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha384Aes192KW, EncryptionAlgorithms.ContentEncryption.Aes192Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha512Aes256KW, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	public async Task Pbes2_JweRoundTrip_Success(string keyManagementAlgorithm, string contentEncryption)
	{
		// Arrange
		var passwordKey = CreateAppendixCPasswordKey();
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
		var token = CreateTestToken();

		// Act: Encrypt
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwe = await creator.IssueAsync(token, signingKey, passwordKey, keyManagementAlgorithm, contentEncryption);

		// Assert: JWE structure with a non-empty encrypted key
		var parts = jwe.Split('.');
		Assert.Equal(5, parts.Length);
		Assert.NotEmpty(parts[1]);

		// Act: Decrypt and validate
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var result = await validator.ValidateAsync(jwe, new ValidationParameters
		{
			ValidateAudience = aud => Task.FromResult(aud.Contains("test-audience")),
			ValidateIssuer = iss => Task.FromResult(iss == "test-issuer"),
			ResolveTokenDecryptionKeys = _ => passwordKey.ToAsync(),
			ResolveIssuerSigningKeys = _ => signingKey.ToAsync(),
		});

		// Assert: claims round-tripped
		Assert.True(result.TryGetSuccess(out var decrypted));
		Assert.Equal(token.Payload.JwtId, decrypted.Payload.JwtId);
		Assert.Equal("test-value", decrypted.Payload.Json["test-claim"]?.GetValue<string>());
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
