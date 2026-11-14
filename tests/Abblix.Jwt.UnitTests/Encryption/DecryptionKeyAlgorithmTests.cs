// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests.Encryption;

/// <summary>
/// RFC 8725 section 3.1: "each key MUST be used with exactly one algorithm, and this MUST be checked when the
/// cryptographic operation is performed." A decryption key that declares its algorithm opens only a JWE whose
/// <c>alg</c> names that algorithm; a key declaring none stays usable under any.
/// </summary>
public class DecryptionKeyAlgorithmTests
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

	private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);

	[Theory]
	[InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, EncryptionAlgorithms.KeyManagement.RsaOaep256, true)]
	[InlineData(null, EncryptionAlgorithms.KeyManagement.RsaOaep256, true)]
	[InlineData(null, EncryptionAlgorithms.KeyManagement.RsaOaep, true)]
	[InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep256, EncryptionAlgorithms.KeyManagement.RsaOaep, false)]
	[InlineData(EncryptionAlgorithms.KeyManagement.RsaOaep, EncryptionAlgorithms.KeyManagement.RsaOaep256, false)]
	public async Task ADecryptionKey_OpensOnlyTheAlgorithmItDeclares(
		string? declaredAlgorithm,
		string tokenAlgorithm,
		bool opens)
	{
		var keyMaterial = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
		var issuingKey = keyMaterial with { Algorithm = null };
		var decryptionKey = keyMaterial with { Algorithm = declaredAlgorithm };

		var issuedAt = TimeProvider.System.GetUtcNow();
		var token = new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.RS256 },
			Payload =
			{
				Issuer = "test-issuer",
				Audiences = ["test-audience"],
				IssuedAt = issuedAt,
				ExpiresAt = issuedAt.AddMinutes(10),
			},
		};
		var jwe = await ServiceProvider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(
			token,
			SigningKey,
			issuingKey,
			tokenAlgorithm,
			EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256);

		var result = await ServiceProvider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(
			jwe,
			new ValidationParameters
			{
				TokenTypes = TokenTypePolicy.CheckedByCaller,
				Options = ValidationOptions.RequireSignedTokens,
				ResolveIssuerSigningKeys = _ => SigningKey.ToAsync(),
				ResolveTokenDecryptionKeys = _ => decryptionKey.ToAsync(),
			});

		Assert.Equal(opens, result.TryGetSuccess(out _));
		if (!opens)
		{
			Assert.True(result.TryGetFailure(out var error));
			Assert.Equal(JwtError.InvalidToken, error.Error);
		}
	}
}
