// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests.Encryption;

/// <summary>
/// RFC 7518 section 5.3: "Use of an IV of size 96 bits is REQUIRED with this algorithm. The requested size of the
/// Authentication Tag output MUST be 128 bits, regardless of the key size." A JWE whose IV or authentication tag
/// has another length is refused as a validation result, whatever the length.
/// </summary>
public class AesGcmContentEncryptionTests
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

	private static readonly OctetJsonWebKey SharedKey = new()
	{
		KeyId = "shared-key",
		Algorithm = EncryptionAlgorithms.KeyManagement.Dir,
		KeyValue = CryptoRandom.GetRandomBytes(16),
	};

	private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

	[Fact]
	public async Task AnUntouchedToken_Validates()
	{
		var result = await ValidateAsync(await IssueAsync());

		Assert.True(result.TryGetSuccess(out _));
	}

	/// <summary>
	/// A tag cut to its first octets still verifies under a GCM instance built for the shorter length, so the length
	/// has to be checked rather than taken from the token.
	/// </summary>
	[Theory]
	[InlineData(12)]
	[InlineData(13)]
	[InlineData(15)]
	[InlineData(0)]
	public async Task ATagShorterThan128Bits_IsRefused(int tagLength)
	{
		var parts = (await IssueAsync()).Split('.');
		parts[4] = Base64Url.EncodeToString(Base64Url.DecodeFromChars(parts[4]).AsSpan(0, tagLength));

		var result = await ValidateAsync(string.Join('.', parts));

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidToken, error.Error);
	}

	[Fact]
	public async Task ATagLongerThan128Bits_IsRefused()
	{
		var parts = (await IssueAsync()).Split('.');
		parts[4] = Base64Url.EncodeToString([.. Base64Url.DecodeFromChars(parts[4]), 0]);

		var result = await ValidateAsync(string.Join('.', parts));

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidToken, error.Error);
	}

	[Theory]
	[InlineData(8)]
	[InlineData(11)]
	[InlineData(13)]
	[InlineData(16)]
	public async Task AnInitializationVectorOtherThan96Bits_IsRefused(int ivLength)
	{
		var parts = (await IssueAsync()).Split('.');
		parts[2] = Base64Url.EncodeToString(new byte[ivLength]);

		var result = await ValidateAsync(string.Join('.', parts));

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidToken, error.Error);
	}

	private static async Task<string> IssueAsync()
	{
		var issuedAt = TimeProvider.System.GetUtcNow();
		var token = new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.RS256 },
			Payload =
			{
				Issuer = "test-issuer",
				Audiences = ["test-audience"],
				IssuedAt = issuedAt,
				NotBefore = issuedAt,
				ExpiresAt = issuedAt.AddMinutes(10),
			},
		};

		var creator = ServiceProvider.GetRequiredService<IJsonWebTokenCreator>();
		return await creator.IssueAsync(
			token,
			SigningKey,
			SharedKey,
			EncryptionAlgorithms.KeyManagement.Dir,
			EncryptionAlgorithms.ContentEncryption.Aes128Gcm);
	}

	private static Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(string jwt)
	{
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();
		return validator.ValidateAsync(jwt, new ValidationParameters
		{
			TokenTypes = TokenTypePolicy.CheckedByCaller,
			ValidateAudience = _ => Task.FromResult(true),
			ValidateIssuer = _ => Task.FromResult(true),
			ResolveTokenDecryptionKeys = _ => SharedKey.ToAsync(),
			ResolveIssuerSigningKeys = _ => SigningKey.ToAsync(),
		});
	}
}
