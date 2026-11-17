// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using Abblix.Jwt.Encryption;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests.Encryption;

/// <summary>
/// Keys are matched to a key management algorithm by the registry the algorithms are advertised from: a built-in one,
/// and one a host registers under its own name, is served by a key of the type it is registered for whether or not the
/// key declares it.
/// </summary>
public class HostKeyManagementAlgorithmTests
{
	/// <summary>The name a host registers its RSA key management algorithm under.</summary>
	private const string HostAlgorithm = "X-HOST-RSA-OAEP-256";

	private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

	private static IServiceProvider CreateServiceProvider()
	{
		var services = new ServiceCollection();
		services.AddSingleton(TimeProvider.System);
		services.AddLogging();
		services.AddJsonWebTokens();
		services.AddRsaPkcs1KeyManagement();
		services.AddPbes2KeyManagement();
		services.AddKeyedSingleton<IKeyManagementAlgorithm<RsaJsonWebKey>>(
			HostAlgorithm,
			(serviceProvider, _) => new Renamed(
				serviceProvider.GetRequiredKeyedService<IKeyManagementAlgorithm<RsaJsonWebKey>>(
					EncryptionAlgorithms.KeyManagement.RsaOaep256)));
		return services.BuildServiceProvider();
	}

	/// <summary>
	/// A host's algorithm, carried out by a built-in one under another name.
	/// </summary>
	private sealed class Renamed(IKeyManagementAlgorithm<RsaJsonWebKey> inner) : IKeyManagementAlgorithm<RsaJsonWebKey>
	{
		public string Algorithm => HostAlgorithm;

		public byte[] EncryptKey(JsonWebTokenHeader header, RsaJsonWebKey encryptionKey, byte[] keyToEncrypt)
			=> inner.EncryptKey(header, encryptionKey, keyToEncrypt);

		public bool TryDecryptKey(
			JsonWebTokenHeader header,
			RsaJsonWebKey decryptingKey,
			byte[] encryptedKey,
			[NotNullWhen(true)] out byte[]? decryptedKey)
			=> inner.TryDecryptKey(header, decryptingKey, encryptedKey, out decryptedKey);
	}

	/// <summary>
	/// A JWE encrypted under the host's algorithm opens with an RSA key of the server, whether the key declares that
	/// algorithm or none (RFC 7517 section 4.4 makes alg optional, and a key imported from a certificate never has
	/// one), as discovery and registration, which list the algorithm from the same registry, promise.
	/// </summary>
	[Theory]
	[InlineData(null)]
	[InlineData(HostAlgorithm)]
	public async Task AJweUnderTheHostsAlgorithm_OpensWithAnRsaKey(string? declaredAlgorithm)
	{
		var keyMaterial = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
		var token = new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.None },
			Payload = { Issuer = "test-issuer", Subject = "user-1" },
		};
		var jwe = await ServiceProvider.GetRequiredService<IJsonWebTokenCreator>().EncryptClaimsAsync(
			token,
			keyMaterial with { Algorithm = null },
			HostAlgorithm,
			EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256);

		var plaintext = await ServiceProvider.GetRequiredService<IJsonWebTokenEncryptor>().DecryptAsync(
			jwe.Split('.'),
			(keyMaterial with { Algorithm = declaredAlgorithm }).ToAsync(),
			TestContext.Current.CancellationToken);

		Assert.True(plaintext.TryGetSuccess(out _));
	}

	/// <summary>
	/// The algorithm is performed by keys of the type it is registered for alone, and by a key declaring another
	/// algorithm by none (RFC 8725 section 3.1: "each key MUST be used with exactly one algorithm").
	/// </summary>
	[Fact]
	public void TheHostsAlgorithm_IsPerformedByTheKeyTypeItIsRegisteredFor()
	{
		var algorithms = ServiceProvider.GetRequiredService<EncryptionAlgorithmsProvider>();
		var rsa = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption) with { Algorithm = null };

		Assert.Contains(HostAlgorithm, algorithms.KeyManagementAlgorithms);
		Assert.True(algorithms.CanEncrypt(rsa, HostAlgorithm));
		Assert.True(algorithms.CanEncrypt(rsa with { Algorithm = HostAlgorithm }, HostAlgorithm));
		Assert.False(algorithms.CanEncrypt(rsa with { Algorithm = EncryptionAlgorithms.KeyManagement.RsaOaep256 }, HostAlgorithm));
		Assert.False(algorithms.CanEncrypt(
			JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256) with { Algorithm = null },
			HostAlgorithm));
		Assert.False(algorithms.CanEncrypt(JsonWebKeyFactory.CreateHmac(SigningAlgorithms.HS256) with { Algorithm = null }, HostAlgorithm));
	}

	/// <summary>
	/// Every key management algorithm the library names, its opt-ins registered, is performed by a key of the type
	/// RFC 7518 section 4.1 gives it, and by no key of another type.
	/// </summary>
	[Theory]
	[InlineData(EncryptionAlgorithms.KeyManagement.Rsa1_5, JsonWebKeyTypes.Rsa)]
	[InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep, JsonWebKeyTypes.Rsa)]
	[InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, JsonWebKeyTypes.Rsa)]
	[InlineData(EncryptionAlgorithms.KeyManagement.EcdhEs, JsonWebKeyTypes.EllipticCurve)]
	[InlineData(EncryptionAlgorithms.KeyManagement.EcdhEsAes128KW, JsonWebKeyTypes.EllipticCurve)]
	[InlineData(EncryptionAlgorithms.KeyManagement.EcdhEsAes192KW, JsonWebKeyTypes.EllipticCurve)]
	[InlineData(EncryptionAlgorithms.KeyManagement.EcdhEsAes256KW, JsonWebKeyTypes.EllipticCurve)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes128KW, JsonWebKeyTypes.Octet)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes192KW, JsonWebKeyTypes.Octet)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes256KW, JsonWebKeyTypes.Octet)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes128Gcmkw, JsonWebKeyTypes.Octet)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes192Gcmkw, JsonWebKeyTypes.Octet)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Aes256Gcmkw, JsonWebKeyTypes.Octet)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Dir, JsonWebKeyTypes.Octet)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha256Aes128KW, JsonWebKeyTypes.Octet)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha384Aes192KW, JsonWebKeyTypes.Octet)]
	[InlineData(EncryptionAlgorithms.KeyManagement.Pbes2HmacSha512Aes256KW, JsonWebKeyTypes.Octet)]
	public void ABuiltInAlgorithm_IsPerformedByItsKeyTypeAlone(string algorithm, string keyType)
	{
		var algorithms = ServiceProvider.GetRequiredService<EncryptionAlgorithmsProvider>();
		JsonWebKey[] keys =
		[
			JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption) with { Algorithm = null },
			JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, SigningAlgorithms.ES256) with { Algorithm = null },
			JsonWebKeyFactory.CreateHmac(SigningAlgorithms.HS256) with { Algorithm = null },
		];

		Assert.Equal(
			[keyType],
			keys.Where(key => algorithms.CanEncrypt(key, algorithm)).Select(key => key.KeyType));
	}
}
