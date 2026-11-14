// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text;
using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests.Encryption;

/// <summary>
/// RFC 7516 section 4.1.3 says of "zip" that "This Header Parameter MUST be understood and processed by
/// implementations", and RFC 8725 section 3.6 that "Compression of data SHOULD NOT be done before encryption". The
/// library decompresses nothing, so a JWE naming a compression algorithm is refused as RFC 7516 section 5.2 step 5
/// orders, before any key is tried.
/// </summary>
public class JweCompressionTests
{
	private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
	private static readonly JsonWebKey EncryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);

	private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

	private static IServiceProvider CreateServiceProvider()
	{
		var services = new ServiceCollection();
		services.AddSingleton(TimeProvider.System);
		services.AddLogging();
		services.AddJsonWebTokens();
		return services.BuildServiceProvider();
	}

	[Theory]
	[InlineData("DEF")]
	[InlineData("unknown")]
	public async Task AJweNamingACompressionAlgorithm_IsRefusedBeforeAnyKey(string compression)
	{
		var parts = (await IssueAsync()).Split('.');
		var header = JsonNode.Parse(Base64Url.DecodeFromChars(parts[0]))!.AsObject();
		header[JwtClaimTypes.CompressionAlgorithm] = compression;
		parts[0] = Base64Url.EncodeToString(Encoding.UTF8.GetBytes(header.ToJsonString()));

		var (result, keysRead) = await ValidateAsync(string.Join('.', parts));

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidHeader, error.Error);
		Assert.Equal(0, keysRead);
	}

	[Fact]
	public async Task AJweWithoutCompression_Validates()
	{
		var (result, keysRead) = await ValidateAsync(await IssueAsync());

		Assert.True(result.TryGetSuccess(out _));
		Assert.Equal(1, keysRead);
	}

	private static Task<string> IssueAsync()
	{
		var token = new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.RS256 },
			Payload = { Issuer = "test-issuer", Audiences = ["test-audience"] },
		};
		return ServiceProvider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, SigningKey, EncryptionKey);
	}

	private static async Task<(Abblix.Utils.Result<JsonWebToken, JwtValidationError> Result, int KeysRead)> ValidateAsync(
		string jwe)
	{
		var keysRead = 0;
		var result = await ServiceProvider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(
			jwe,
			new ValidationParameters
			{
				TokenTypes = TokenTypePolicy.CheckedByCaller,
				Options = ValidationOptions.RequireSignedTokens,
				ResolveIssuerSigningKeys = _ => new[] { SigningKey }.ToAsyncEnumerable(),
				ResolveTokenDecryptionKeys = _ => new[] { EncryptionKey }.ToAsyncEnumerable()
					.Select(key =>
					{
						keysRead++;
						return key;
					}),
			});
		return (result, keysRead);
	}
}
