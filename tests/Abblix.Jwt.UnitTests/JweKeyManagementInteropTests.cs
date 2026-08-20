// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// Bidirectional interoperability tests for the AES Key Wrap (RFC 3394) and ECDH-ES key management
/// families against Microsoft's IdentityModel stack: a JWE encrypted by either side must decrypt on
/// the other. PBES2 has no counterpart in that stack, so its cross-validation is the RFC 7517
/// Appendix C known-answer vector in <see cref="Pbes2KeyEncryptionTests"/>.
/// </summary>
/// <remarks>
/// The Microsoft stack constrains the interop matrix: its JWE content encryption is limited to the
/// AES-CBC-HMAC family, ECDH-ES exists only in the key-wrapping variants (its Direct Key Agreement
/// mode uses the decryption key itself as the CEK instead of deriving one), and its ECDH encrypt
/// path hard-ties the CEK size to the wrap size, pinning each ECDH-ES+A*KW to the same-strength
/// CBC-HMAC pairing. The combinations it cannot produce or consume are covered by the RFC
/// known-answer vectors and the round-trip suites in <see cref="AesKeyWrapTests"/> and
/// <see cref="EcdhEsKeyAgreementTests"/>.
/// </remarks>
public class JweKeyManagementInteropTests
{
	private const string Issuer = "https://issuer.example.com";
	private const string Audience = "https://audience.example.com";
	private const string SubjectId = "interop-user";
	private const string ValidationFailed = "Validation failed";

	private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

	private static IServiceProvider CreateServiceProvider()
	{
		var services = new ServiceCollection();
		services.AddSingleton(TimeProvider.System);
		services.AddLogging();
		services.AddJsonWebTokens();
		return services.BuildServiceProvider();
	}

	private readonly JsonWebTokenHandler _microsoftHandler = new()
	{
		MapInboundClaims = false
	};

	public static TheoryData<string, string, int, string, string> SymmetricKeyWrapAlgorithms => new()
	{
		// Every AES Key Wrap size × the AES-CBC-HMAC content encryptions both stacks implement
		{ EncryptionAlgorithms.KeyManagement.Aes128KW, SecurityAlgorithms.Aes128KW, 16,
		  EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256, SecurityAlgorithms.Aes128CbcHmacSha256 },
		{ EncryptionAlgorithms.KeyManagement.Aes128KW, SecurityAlgorithms.Aes128KW, 16,
		  EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512, SecurityAlgorithms.Aes256CbcHmacSha512 },
		{ EncryptionAlgorithms.KeyManagement.Aes192KW, SecurityAlgorithms.Aes192KW, 24,
		  EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384, SecurityAlgorithms.Aes192CbcHmacSha384 },
		{ EncryptionAlgorithms.KeyManagement.Aes256KW, SecurityAlgorithms.Aes256KW, 32,
		  EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256, SecurityAlgorithms.Aes128CbcHmacSha256 },
		{ EncryptionAlgorithms.KeyManagement.Aes256KW, SecurityAlgorithms.Aes256KW, 32,
		  EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512, SecurityAlgorithms.Aes256CbcHmacSha512 },
	};

	[Theory]
	[MemberData(nameof(SymmetricKeyWrapAlgorithms))]
	public async Task Create_AbblixAesKeyWrapJwt_MicrosoftDecrypts_Success(
		string abblixKeyEncAlg,
		string microsoftKeyEncAlg,
		int keyEncryptionKeySize,
		string abblixContentEncAlg,
		string microsoftContentEncAlg)
	{
		// Arrange
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
		var keyEncryptionKey = CreateKeyEncryptionKey(abblixKeyEncAlg, keyEncryptionKeySize);

		// Abblix creates the signed and encrypted JWT
		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		var jwt = await creator.IssueAsync(
			CreateAbblixToken(), signingKey, keyEncryptionKey, abblixKeyEncAlg, abblixContentEncAlg);

		// Act - Microsoft decrypts and validates
		var result = await _microsoftHandler.ValidateTokenAsync(jwt, new TokenValidationParameters
		{
			ValidateIssuerSigningKey = true,
			IssuerSigningKey = signingKey.ToSecurityKey(),
			ValidIssuer = Issuer,
			ValidAudience = Audience,
			TokenDecryptionKey = new EncryptingCredentials(
				keyEncryptionKey.ToSecurityKey(), microsoftKeyEncAlg, microsoftContentEncAlg).Key,
		});

		// Assert
		Assert.True(result.IsValid,
			$"Validation failed for {abblixKeyEncAlg}/{abblixContentEncAlg}: {result.Exception?.Message}");
		Assert.Equal(SubjectId, result.ClaimsIdentity.FindFirst("sub")?.Value);
	}

	[Theory]
	[MemberData(nameof(SymmetricKeyWrapAlgorithms))]
	public async Task Create_MicrosoftAesKeyWrapJwt_AbblixDecrypts_Success(
		string abblixKeyEncAlg,
		string microsoftKeyEncAlg,
		int keyEncryptionKeySize,
		string abblixContentEncAlg,
		string microsoftContentEncAlg)
	{
		// Arrange
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
		var keyEncryptionKey = CreateKeyEncryptionKey(abblixKeyEncAlg, keyEncryptionKeySize);

		// Microsoft creates the signed and encrypted JWT
		var descriptor = new SecurityTokenDescriptor
		{
			Subject = new System.Security.Claims.ClaimsIdentity([
				new System.Security.Claims.Claim("sub", SubjectId),
			]),
			Issuer = Issuer,
			Audience = Audience,
			Expires = TimeProvider.System.GetUtcNow().UtcDateTime.AddHours(1),
			SigningCredentials = new SigningCredentials(signingKey.ToSecurityKey(), SecurityAlgorithms.RsaSha256),
			EncryptingCredentials = new EncryptingCredentials(
				keyEncryptionKey.ToSecurityKey(), microsoftKeyEncAlg, microsoftContentEncAlg),
		};

		var jwt = _microsoftHandler.CreateToken(descriptor);

		// Act - Abblix decrypts and validates
		var result = await ValidateWithAbblix(jwt, signingKey, keyEncryptionKey);

		// Assert
		Assert.True(result.TryGetSuccess(out var token),
			result.TryGetFailure(out var error)
				? $"Validation failed for {abblixKeyEncAlg}/{abblixContentEncAlg}: {error.Error} - {error.ErrorDescription}"
				: ValidationFailed);
		Assert.Equal(SubjectId, token.Payload.Subject);
	}

	// The canonical ECDH-ES+A*KW pairings both stacks agree on. The Microsoft encrypt path hard-ties
	// the CEK size to the key wrap size (A128KW → 256-bit CEK, A192KW → 384, A256KW → 512), which
	// pins each wrap to its same-strength AES-CBC-HMAC content encryption.
	public static TheoryData<string, string, int, int> EcdhEsKeyWrapAlgorithms => new()
	{
		{ EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW, EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256, 16, 32 },
		{ EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW, EncryptionAlgorithms.ContentEncryption.Aes192CbcHmacSha384, 24, 48 },
		{ EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW, EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512, 32, 64 },
	};

	// The ECDH-ES cross-validation runs against the Microsoft cryptographic primitives
	// (EcdhKeyExchangeProvider + SymmetricKeyWrapProvider) rather than JsonWebTokenHandler: the
	// handler emits the RFC-defined 'epk'/'kid' headers only under the process-wide AppContext
	// switch "Switch.Microsoft.IdentityModel.UseRfcDefinitionOfEpkAndKid" (its default mode omits
	// 'epk' and derives from the recipient key against itself), and enabling that cached switch
	// breaks the handler's own RSA/AES-KW JWE writer on a null KeyExchangePublicKey - the two modes
	// cannot coexist in one test process. The primitive level is exactly the cryptographic contract
	// interop must prove: both sides derive the same KEK from the same agreement parameters and
	// unwrap each other's wrapped CEKs.

	[Theory]
	[MemberData(nameof(EcdhEsKeyWrapAlgorithms))]
	public void Create_AbblixEcdhEsWrappedKey_MicrosoftPrimitivesUnwrap_Success(
		string keyEncAlg,
		string contentEncAlg,
		int keyEncryptionKeySize,
		int contentEncryptionKeySize)
	{
		// Arrange: recipient EC key and a header carrying the agreement parties
		var recipientKey = JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);
		var header = new JsonWebTokenHeader(new JsonObject())
		{
			Algorithm = keyEncAlg,
			EncryptionAlgorithm = contentEncAlg,
			AgreementPartyUInfo = "QWxpY2U",
			AgreementPartyVInfo = "Qm9i",
		};

		// Abblix derives the KEK, wraps a random CEK and publishes 'epk'
		var encryptor = new EcdhEsKeyEncryptor(keyEncAlg, ServiceProvider);
		var contentEncryptionKey = encryptor.GenerateContentEncryptionKey(header, recipientKey, contentEncryptionKeySize);
		var encryptedKey = encryptor.EncryptKey(header, recipientKey, contentEncryptionKey);

		// Act - the Microsoft primitives re-derive the KEK from the recipient private key and our 'epk',
		// then unwrap the CEK
		var ephemeralPublicKey = new Microsoft.IdentityModel.Tokens.JsonWebKey(
			header.Json[JwtClaimTypes.EphemeralPublicKey]!.ToJsonString());
		var exchangeProvider = new EcdhKeyExchangeProvider(
			(ECDsaSecurityKey)recipientKey.ToSecurityKey(), ephemeralPublicKey, keyEncAlg, contentEncAlg);
		var kdf = exchangeProvider.GenerateKdf(header.AgreementPartyUInfo, header.AgreementPartyVInfo);

		Assert.Equal(keyEncryptionKeySize, ((SymmetricSecurityKey)kdf).Key.Length);

		var keyWrapProvider = kdf.CryptoProviderFactory.CreateKeyWrapProviderForUnwrap(
			kdf, ToKeyWrapAlgorithm(keyEncAlg));
		var unwrappedKey = keyWrapProvider.UnwrapKey(encryptedKey);

		// Assert - byte-exact agreement across the whole KDF + RFC 3394 pipeline
		Assert.Equal(contentEncryptionKey, unwrappedKey);
	}

	[Theory]
	[MemberData(nameof(EcdhEsKeyWrapAlgorithms))]
	public void Create_MicrosoftEcdhEsWrappedKey_AbblixDecrypts_Success(
		string keyEncAlg,
		string contentEncAlg,
		int keyEncryptionKeySize,
		int contentEncryptionKeySize)
	{
		// Arrange: the Microsoft primitives act as the producer - the sender key plays the ephemeral
		// role and its public part travels as 'epk', exactly what their RFC-mode handler would emit
		var recipientKey = JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);
		var senderKey = JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256);

		var recipientPublicKey = Microsoft.IdentityModel.Tokens.JsonWebKeyConverter.ConvertFromECDsaSecurityKey(
			(ECDsaSecurityKey)((EllipticCurveJsonWebKey)recipientKey.Sanitize(includePrivateKeys: false)).ToSecurityKey());
		var exchangeProvider = new EcdhKeyExchangeProvider(
			(ECDsaSecurityKey)senderKey.ToSecurityKey(), recipientPublicKey, keyEncAlg, contentEncAlg);
		var kdf = exchangeProvider.GenerateKdf("QWxpY2U", "Qm9i");

		Assert.Equal(keyEncryptionKeySize, ((SymmetricSecurityKey)kdf).Key.Length);

		var contentEncryptionKey = CryptoRandom.GetRandomBytes(contentEncryptionKeySize);
		var keyWrapProvider = kdf.CryptoProviderFactory.CreateKeyWrapProvider(
			kdf, ToKeyWrapAlgorithm(keyEncAlg));
		var encryptedKey = keyWrapProvider.WrapKey(contentEncryptionKey);

		var header = new JsonWebTokenHeader(new JsonObject())
		{
			Algorithm = keyEncAlg,
			EncryptionAlgorithm = contentEncAlg,
			AgreementPartyUInfo = "QWxpY2U",
			AgreementPartyVInfo = "Qm9i",
			EphemeralPublicKey = (EllipticCurveJsonWebKey)senderKey.Sanitize(includePrivateKeys: false),
		};

		// Act - Abblix re-derives the KEK from the recipient private key and their 'epk', then unwraps
		var encryptor = new EcdhEsKeyEncryptor(keyEncAlg, ServiceProvider);
		var succeeded = encryptor.TryDecryptKey(header, recipientKey, encryptedKey, out var unwrappedKey);

		// Assert - byte-exact agreement across the whole KDF + RFC 3394 pipeline
		Assert.True(succeeded, $"Abblix failed to unwrap the Microsoft-wrapped CEK for {keyEncAlg}/{contentEncAlg}");
		Assert.Equal(contentEncryptionKey, unwrappedKey);
	}

	/// <summary>
	/// The RFC 3394 wrap algorithm behind each ECDH-ES key-wrapping variant, per RFC 7518 §4.6:
	/// the derived key is used as the KEK for the corresponding "A*KW" algorithm.
	/// </summary>
	private static string ToKeyWrapAlgorithm(string keyEncAlg) => keyEncAlg switch
	{
		EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW => SecurityAlgorithms.Aes128KW,
		EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW => SecurityAlgorithms.Aes192KW,
		_ => SecurityAlgorithms.Aes256KW,
	};

	private static OctetJsonWebKey CreateKeyEncryptionKey(string algorithm, int size) => new()
	{
		KeyId = $"interop-kek-{size * 8}",
		Algorithm = algorithm,
		KeyValue = CryptoRandom.GetRandomBytes(size),
	};

	private static JsonWebToken CreateAbblixToken()
	{
		var issuedAt = TimeProvider.System.GetUtcNow();

		return new JsonWebToken
		{
			Header = { Type = "JWT" },
			Payload =
			{
				Subject = SubjectId,
				Issuer = Issuer,
				Audiences = [Audience],
				IssuedAt = issuedAt,
				ExpiresAt = issuedAt + TimeSpan.FromHours(1),
			},
		};
	}

	private static async Task<Result<JsonWebToken, JwtValidationError>> ValidateWithAbblix(
		string jwt,
		JsonWebKey signingKey,
		JsonWebKey decryptionKey)
	{
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		return await validator.ValidateAsync(jwt, new ValidationParameters
		{
			Options = ValidationOptions.ValidateIssuer |
			          ValidationOptions.ValidateAudience |
			          ValidationOptions.RequireSignedTokens |
			          ValidationOptions.ValidateIssuerSigningKey,
			ValidateIssuer = iss => Task.FromResult(iss == Issuer),
			ValidateAudience = aud => Task.FromResult(aud.Contains(Audience)),
			ResolveIssuerSigningKeys = _ => signingKey.ToAsync(),
			ResolveTokenDecryptionKeys = _ => decryptionKey.ToAsync(),
		});
	}
}
