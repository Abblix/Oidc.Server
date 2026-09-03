// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Tests for ECDH-ES key agreement (RFC 7518 Section 4.6). The canonical Appendix C example pins
/// the Concat KDF byte-exact (OtherInfo layout, round counter, truncation), JWE round-trips cover
/// Direct Key Agreement and the RFC 3394 key-wrapping variants across all NIST curves, and the
/// negative tests exercise the header validation the spec mandates.
/// </summary>
public class EcdhEsKeyAgreementTests
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
	/// The consumer's (Bob's) static P-256 key from RFC 7518 Appendix C, private part included.
	/// </summary>
	private static EllipticCurveJsonWebKey CreateAppendixCRecipientKey() => new()
	{
		KeyId = "bob",
		Curve = EllipticCurveTypes.P256,
		X = Base64Url.DecodeFromChars("weNJy2HscCSM6AEDTDg04biOvhFhyyWvOHQfeF_PxMQ"),
		Y = Base64Url.DecodeFromChars("e8lnCO-AlStT-NJVX-crhB7QRYhiix03illJOVAOyck"),
		PrivateKey = Base64Url.DecodeFromChars("VEmDZpDXXK8p8N0Cndsxs924q6nS1RXFASRl6BfUqdw"),
	};

	/// <summary>
	/// The JWE header of RFC 7518 Appendix C: ECDH-ES Direct Key Agreement for A128GCM with
	/// Alice's ephemeral public key as 'epk', apu = base64url("Alice"), apv = base64url("Bob").
	/// </summary>
	private static JsonWebTokenHeader CreateAppendixCHeader() => new(new JsonObject
	{
		[JwtClaimTypes.Algorithm] = EncryptionAlgorithms.KeyManagement.EcdhEs,
		[JwtClaimTypes.EncryptionAlgorithm] = EncryptionAlgorithms.ContentEncryption.Aes128Gcm,
		[JwtClaimTypes.AgreementPartyUInfo] = "QWxpY2U",
		[JwtClaimTypes.AgreementPartyVInfo] = "Qm9i",
		[JwtClaimTypes.EphemeralPublicKey] = new JsonObject
		{
			[JsonWebKeyPropertyNames.KeyType] = JsonWebKeyTypes.EllipticCurve,
			[JsonWebKeyPropertyNames.Curve] = EllipticCurveTypes.P256,
			[JsonWebKeyPropertyNames.EllipticCurveX] = "gI0GAILBdu7T53akrFmMyGcsF3n5dO7MmwNBHKW5SV0",
			[JsonWebKeyPropertyNames.EllipticCurveY] = "SLW_xSffzlPWrHEVI30DHM_4egVwt3NQqeUD7nMFpps",
		},
	});

	/// <summary>
	/// RFC 7518 Appendix C, the canonical worked ECDH-ES example: deriving with Bob's private key
	/// and Alice's ephemeral public key must yield exactly the 128-bit CEK the appendix lists.
	/// This known-answer test pins the whole Concat KDF construction - the length-prefixed
	/// AlgorithmID/PartyUInfo/PartyVInfo, the SuppPubInfo bit length, the round counter and the
	/// hash-output truncation.
	/// </summary>
	[Fact]
	public void TryDecryptKey_Rfc7518AppendixC_DerivesExpectedCek()
	{
		var encryptor = new EcdhEsKeyEncryptor(EncryptionAlgorithms.KeyManagement.EcdhEs, ServiceProvider);

		var succeeded = encryptor.TryDecryptKey(
			CreateAppendixCHeader(), CreateAppendixCRecipientKey(), [], out var contentEncryptionKey);

		Assert.True(succeeded);
		Assert.Equal("VqqN6vgjbSBcIijNcacQGg", Base64Url.EncodeToString(contentEncryptionKey));
	}

	/// <summary>
	/// RFC 7518 section 4.6: in Direct Key Agreement mode the JWE Encrypted Key is the empty octet
	/// sequence - a non-empty value signals a malformed or tampered token and must be rejected.
	/// </summary>
	[Fact]
	public void TryDecryptKey_DirectModeWithNonEmptyEncryptedKey_Fails()
	{
		var encryptor = new EcdhEsKeyEncryptor(EncryptionAlgorithms.KeyManagement.EcdhEs, ServiceProvider);

		var succeeded = encryptor.TryDecryptKey(
			CreateAppendixCHeader(), CreateAppendixCRecipientKey(), CryptoRandom.GetRandomBytes(16), out var contentEncryptionKey);

		Assert.False(succeeded);
		Assert.Null(contentEncryptionKey);
	}

	/// <summary>
	/// RFC 7518 section 4.6.2: when both PartyUInfo and PartyVInfo are present they must be distinct -
	/// equal values collapse the producer and recipient identities the KDF is meant to bind.
	/// </summary>
	[Fact]
	public void TryDecryptKey_EqualApuAndApv_Fails()
	{
		var header = CreateAppendixCHeader();
		header.AgreementPartyUInfo = "QWxpY2U";
		header.AgreementPartyVInfo = "QWxpY2U";

		var encryptor = new EcdhEsKeyEncryptor(EncryptionAlgorithms.KeyManagement.EcdhEs, ServiceProvider);

		Assert.False(encryptor.TryDecryptKey(header, CreateAppendixCRecipientKey(), [], out _));
	}

	[Fact]
	public void TryDecryptKey_MissingEphemeralKey_Fails()
	{
		var header = CreateAppendixCHeader();
		header.Json.Remove(JwtClaimTypes.EphemeralPublicKey);

		var encryptor = new EcdhEsKeyEncryptor(EncryptionAlgorithms.KeyManagement.EcdhEs, ServiceProvider);

		Assert.False(encryptor.TryDecryptKey(header, CreateAppendixCRecipientKey(), [], out _));
	}

	/// <summary>
	/// An ephemeral key on a curve different from the recipient key's makes the agreement
	/// meaningless (and is the classic invalid-curve attack shape) - it must be rejected
	/// before any computation.
	/// </summary>
	[Fact]
	public void TryDecryptKey_EphemeralKeyOnDifferentCurve_Fails()
	{
		var foreignCurveKey = JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P384, SigningAlgorithms.ES384);

		var header = CreateAppendixCHeader();
		header.EphemeralPublicKey = (EllipticCurveJsonWebKey)foreignCurveKey.Sanitize(includePrivateKeys: false);

		var encryptor = new EcdhEsKeyEncryptor(EncryptionAlgorithms.KeyManagement.EcdhEs, ServiceProvider);

		Assert.False(encryptor.TryDecryptKey(header, CreateAppendixCRecipientKey(), [], out _));
	}

	/// <summary>
	/// Tampered ephemeral coordinates produce a point that is not on the curve; the platform
	/// rejects it during import and no key material may come back. Accepting such a point would
	/// open the invalid-curve attack on the recipient's static private key.
	/// </summary>
	[Fact]
	public void TryDecryptKey_TamperedEphemeralCoordinates_Fails()
	{
		var header = CreateAppendixCHeader();
		var epk = (JsonObject)header.Json[JwtClaimTypes.EphemeralPublicKey]!;
		var x = Base64Url.DecodeFromChars(epk[JsonWebKeyPropertyNames.EllipticCurveX]!.GetValue<string>());
		x[0] ^= 0x01;
		epk[JsonWebKeyPropertyNames.EllipticCurveX] = Base64Url.EncodeToString(x);

		var encryptor = new EcdhEsKeyEncryptor(EncryptionAlgorithms.KeyManagement.EcdhEs, ServiceProvider);

		Assert.False(encryptor.TryDecryptKey(header, CreateAppendixCRecipientKey(), [], out _));
	}

	/// <summary>
	/// The encryption side must generate a fresh ephemeral key on the recipient's curve, publish
	/// it as 'epk' with public members only, and derive a CEK the recipient can re-derive from
	/// that header - the round-trip at the encryptor level, independent of content encryption.
	/// </summary>
	[Fact]
	public void GenerateContentEncryptionKey_DirectMode_PublishesEpkAndDerivesRecoverableCek()
	{
		var recipientKey = CreateAppendixCRecipientKey();
		var header = new JsonWebTokenHeader(new JsonObject())
		{
			Algorithm = EncryptionAlgorithms.KeyManagement.EcdhEs,
			EncryptionAlgorithm = EncryptionAlgorithms.ContentEncryption.Aes256Gcm,
		};

		var encryptor = new EcdhEsKeyEncryptor(EncryptionAlgorithms.KeyManagement.EcdhEs, ServiceProvider);

		// Act: encryption-side derivation
		var contentEncryptionKey = encryptor.GenerateContentEncryptionKey(header, recipientKey, 32);
		var encryptedKey = encryptor.EncryptKey(header, recipientKey, contentEncryptionKey);

		// Assert: 'epk' carries a public-only EC key on the recipient's curve; encrypted key is empty
		Assert.Empty(encryptedKey);
		var ephemeralKey = Assert.IsType<EllipticCurveJsonWebKey>(header.EphemeralPublicKey);
		Assert.Equal(recipientKey.Curve, ephemeralKey.Curve);
		Assert.True(ephemeralKey.HasPublicKey);
		Assert.False(ephemeralKey.HasPrivateKey);
		Assert.False(((JsonObject)header.Json[JwtClaimTypes.EphemeralPublicKey]!)
			.ContainsKey(JsonWebKeyPropertyNames.PrivateExponent));

		// Assert: the recipient re-derives exactly the same CEK from the published header
		Assert.True(encryptor.TryDecryptKey(header, recipientKey, encryptedKey, out var rederivedKey));
		Assert.Equal(contentEncryptionKey, rederivedKey);
	}

	/// <summary>
	/// Full JWE round-trips: ECDH-ES Direct Key Agreement across every content encryption
	/// algorithm (the CBC-HMAC entries exercise the multi-round Concat KDF for 384/512-bit CEKs)
	/// and every NIST curve.
	/// </summary>
	[Theory]
	[InlineData(EllipticCurveTypes.P256, EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256)]
	[InlineData(EllipticCurveTypes.P256, EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384)]
	[InlineData(EllipticCurveTypes.P256, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	[InlineData(EllipticCurveTypes.P256, EncryptionAlgorithms.ContentEncryption.Aes128Gcm)]
	[InlineData(EllipticCurveTypes.P256, EncryptionAlgorithms.ContentEncryption.Aes192Gcm)]
	[InlineData(EllipticCurveTypes.P256, EncryptionAlgorithms.ContentEncryption.Aes256Gcm)]
	[InlineData(EllipticCurveTypes.P384, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	[InlineData(EllipticCurveTypes.P384, EncryptionAlgorithms.ContentEncryption.Aes256Gcm)]
	[InlineData(EllipticCurveTypes.P521, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	[InlineData(EllipticCurveTypes.P521, EncryptionAlgorithms.ContentEncryption.Aes256Gcm)]
	public async Task EcdhEsDirect_JweRoundTrip_Success(string curve, string contentEncryption)
	{
		await TestEcdhEsRoundTrip(EncryptionAlgorithms.KeyManagement.EcdhEs, curve, contentEncryption, emptyEncryptedKey: true);
	}

	/// <summary>
	/// Full JWE round-trips for the key-wrapping variants: the agreement derives the KEK,
	/// which wraps a random CEK per RFC 3394.
	/// </summary>
	[Theory]
	[InlineData(EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW, EncryptionAlgorithms.ContentEncryption.Aes128Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	[InlineData(EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW, EncryptionAlgorithms.ContentEncryption.Aes192Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	[InlineData(EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW, EncryptionAlgorithms.ContentEncryption.Aes256Gcm)]
	[InlineData(EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512)]
	public async Task EcdhEsWithKeyWrap_JweRoundTrip_Success(string keyManagementAlgorithm, string contentEncryption)
	{
		await TestEcdhEsRoundTrip(keyManagementAlgorithm, EllipticCurveTypes.P256, contentEncryption, emptyEncryptedKey: false);
	}

	/// <summary>
	/// Decrypting with a different EC key than the one the token was encrypted to must fail -
	/// the agreement yields a different CEK and the content authentication tag rejects it.
	/// </summary>
	[Fact]
	public async Task EcdhEs_WrongDecryptionKey_DecryptionFails()
	{
		var recipientKey = JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);
		var wrongKey = JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwe = await creator.IssueAsync(
			CreateTestToken(),
			signingKey,
			recipientKey,
			EncryptionAlgorithms.KeyManagement.EcdhEs,
			EncryptionAlgorithms.ContentEncryption.Aes256Gcm);

		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var result = await validator.ValidateAsync(jwe, CreateValidationParameters(wrongKey, signingKey));

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidToken, error.Error);
	}

	private static async Task TestEcdhEsRoundTrip(
		string keyManagementAlgorithm,
		string curve,
		string contentEncryption,
		bool emptyEncryptedKey)
	{
		// Arrange
		var recipientKey = JsonWebKeyFactory.CreateEllipticCurve(curve, curve switch
		{
			EllipticCurveTypes.P256 => SigningAlgorithms.ES256,
			EllipticCurveTypes.P384 => SigningAlgorithms.ES384,
			_ => SigningAlgorithms.ES512,
		});
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
		var token = CreateTestToken();

		// Act: Encrypt
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwe = await creator.IssueAsync(token, signingKey, recipientKey, keyManagementAlgorithm, contentEncryption);

		// Assert: JWE structure per RFC 7518 section 4.6 - the encrypted key is empty exactly in direct mode
		var parts = jwe.Split('.');
		Assert.Equal(5, parts.Length);
		Assert.Equal(emptyEncryptedKey, parts[1].Length == 0);

		// Act: Decrypt and validate
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		var result = await validator.ValidateAsync(jwe, CreateValidationParameters(recipientKey, signingKey));

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

	private static ValidationParameters CreateValidationParameters(JsonWebKey decryptionKey, JsonWebKey signingKey) => new()
	{
		ValidateAudience = aud => Task.FromResult(aud.Contains("test-audience")),
		ValidateIssuer = iss => Task.FromResult(iss == "test-issuer"),
		ResolveTokenDecryptionKeys = _ => decryptionKey.ToAsync(),
		ResolveIssuerSigningKeys = _ => signingKey.ToAsync(),
	};
}
