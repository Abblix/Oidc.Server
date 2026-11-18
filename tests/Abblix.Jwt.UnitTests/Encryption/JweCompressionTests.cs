// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.IO.Compression;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json.Nodes;
using Abblix.Jwt.Encryption;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.Jwt.UnitTests.Encryption;

/// <summary>
/// RFC 7516 section 4.1.3 says of "zip" that "This Header Parameter MUST be understood and processed by
/// implementations", and section 5.2 step 17: "If a "zip" parameter was included, uncompress the decrypted plaintext
/// using the specified compression algorithm." A JWE compressed with "DEF" (RFC 1951 DEFLATE) opens; any other value
/// is refused before a key is tried; the plaintext is inflated only once its authentication tag has verified, and
/// never past a bound.
/// </summary>
public class JweCompressionTests
{
	private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

	private static readonly OctetJsonWebKey SharedKey = new()
	{
		KeyId = "shared",
		Algorithm = EncryptionAlgorithms.KeyManagement.Dir,
		KeyValue = CryptoRandom.GetRandomBytes(16),
	};

	private readonly RecordingLogger<JweDecryptionLog> _logger = new();
	private readonly IServiceProvider _serviceProvider;

	public JweCompressionTests()
	{
		var services = new ServiceCollection();
		services.AddSingleton(TimeProvider.System);
		services.AddLogging();
		services.AddJsonWebTokens();
		services.AddSingleton<ILogger<JweDecryptionLog>>(_logger);
		_serviceProvider = services.BuildServiceProvider();
	}

	[Fact]
	public async Task ADeflateCompressedNestedJwt_Validates()
	{
		var token = new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.RS256 },
			Payload = { Issuer = "test-issuer", Audiences = ["test-audience"], Subject = "compressed" },
		};
		var jws = await _serviceProvider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, SigningKey);

		var result = await _serviceProvider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(
			Encrypted(Deflated(Encoding.ASCII.GetBytes(jws)), "DEF"),
			new ValidationParameters
			{
				TokenTypes = TokenTypePolicy.CheckedByCaller,
				Options = ValidationOptions.RequireSignedTokens,
				ResolveIssuerSigningKeys = _ => SigningKey.ToAsync(),
				ResolveTokenDecryptionKeys = _ => SharedKey.ToAsync(),
			});

		Assert.True(result.TryGetSuccess(out var validated));
		Assert.Equal("compressed", validated.Payload.Subject);
	}

	[Fact]
	public async Task ADeflateCompressedPlaintext_Opens()
	{
		var plaintext = Encoding.UTF8.GetBytes(string.Concat(Enumerable.Repeat("plaintext ", 100)));

		var result = await DecryptAsync(Encrypted(Deflated(plaintext), "DEF"));

		Assert.True(result.TryGetSuccess(out var opened));
		Assert.Equal(plaintext, opened);
	}

	/// <summary>
	/// A small compressed plaintext can stand for a huge one, so inflation stops at the bound: the token is refused
	/// and far less than its inflated size is ever allocated.
	/// </summary>
	[Fact]
	public async Task APlaintextInflatingPastTheBound_IsRefusedWithoutInflatingIt()
	{
		const int inflatedSize = 64 * 1024 * 1024;
		var jwe = Encrypted(Deflated(new byte[inflatedSize]), "DEF");

		var allocatedBefore = GC.GetAllocatedBytesForCurrentThread();
		var result = await DecryptAsync(jwe);
		var allocated = GC.GetAllocatedBytesForCurrentThread() - allocatedBefore;

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidToken, error.Error);
		Assert.True(allocated < inflatedSize / 8, $"{allocated} bytes were allocated to refuse the token");
	}

	[Fact]
	public async Task APlaintextThatIsNotDeflateData_IsRefused()
	{
		var result = await DecryptAsync(Encrypted([0xFF, 0xFF, 0xFF, 0xFF], "DEF"));

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidToken, error.Error);
	}

	/// <summary>
	/// Inflation follows the tag: a token whose tag does not verify is refused as one no key opened, before its
	/// plaintext is looked at.
	/// </summary>
	[Fact]
	public async Task ATokenWhoseTagFails_IsRefusedBeforeInflation()
	{
		var parts = Encrypted(Deflated(new byte[64 * 1024 * 1024]), "DEF").Split('.');
		var tag = Base64Url.DecodeFromChars(parts[4]);
		tag[0] ^= 1;
		parts[4] = Base64Url.EncodeToString(tag);

		var result = await DecryptAsync(string.Join('.', parts));

		Assert.True(result.TryGetFailure(out _));
		Assert.Equal(LogEvents.Jwt.NoDecryptionKeyOpened, Assert.Single(_logger.Entries).EventId);
	}

	[Theory]
	[InlineData("\"def\"")]
	[InlineData("\"GZIP\"")]
	[InlineData("\"\"")]
	[InlineData("5")]
	[InlineData("null")]
	public async Task AJweNamingAnotherCompression_IsRefusedBeforeAnyKey(string compression)
	{
		var keysRead = 0;
		var result = await _serviceProvider.GetRequiredService<IJsonWebTokenEncryptor>().DecryptAsync(
			Encrypted(Deflated([1, 2, 3]), JsonNode.Parse(compression)).Split('.'),
			SharedKey.ToAsync().Select(key =>
			{
				keysRead++;
				return key;
			}),
			TestContext.Current.CancellationToken);

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidHeader, error.Error);
		Assert.Equal(0, keysRead);
	}

	/// <summary>
	/// RFC 8725 section 3.6: "Compression of data SHOULD NOT be done before encryption". What the library issues is
	/// never compressed.
	/// </summary>
	[Fact]
	public async Task AnIssuedJwe_IsNotCompressed()
	{
		var token = new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.RS256 },
			Payload = { Issuer = "test-issuer", Audiences = ["test-audience"] },
		};
		var jwe = await _serviceProvider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(
			token,
			SigningKey,
			SharedKey,
			EncryptionAlgorithms.KeyManagement.Dir,
			EncryptionAlgorithms.ContentEncryption.Aes128Gcm);

		var header = JsonNode.Parse(Base64Url.DecodeFromChars(jwe.Split('.')[0]))!.AsObject();
		Assert.False(header.ContainsKey(JwtClaimTypes.CompressionAlgorithm));
	}

	private Task<Result<byte[], JwtValidationError>> DecryptAsync(string jwe)
		=> _serviceProvider.GetRequiredService<IJsonWebTokenEncryptor>().DecryptAsync(
			jwe.Split('.'), SharedKey.ToAsync(), TestContext.Current.CancellationToken);

	private static byte[] Deflated(byte[] plaintext)
	{
		using var output = new MemoryStream();
		using (var deflate = new DeflateStream(output, CompressionLevel.SmallestSize))
			deflate.Write(plaintext);
		return output.ToArray();
	}

	/// <summary>A dir + A128GCM JWE whose protected header names <paramref name="compression"/> as its zip.</summary>
	private static string Encrypted(byte[] plaintext, JsonNode? compression)
	{
		var header = new JsonObject
		{
			[JwtClaimTypes.Algorithm] = EncryptionAlgorithms.KeyManagement.Dir,
			[JwtClaimTypes.EncryptionAlgorithm] = EncryptionAlgorithms.ContentEncryption.Aes128Gcm,
			[JwtClaimTypes.KeyId] = SharedKey.KeyId,
			[JwtClaimTypes.CompressionAlgorithm] = compression,
		};
		var encodedHeader = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString()));

		var iv = CryptoRandom.GetRandomBytes(12);
		var ciphertext = new byte[plaintext.Length];
		var tag = new byte[16];
		using (var aesGcm = new AesGcm(SharedKey.KeyValue!, tag.Length))
			aesGcm.Encrypt(iv, plaintext, ciphertext, tag, Encoding.ASCII.GetBytes(encodedHeader));

		return string.Join('.',
			encodedHeader,
			string.Empty,
			Base64Url.EncodeToString(iv),
			Base64Url.EncodeToString(ciphertext),
			Base64Url.EncodeToString(tag));
	}
}
