// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// RFC 7519 section 7.2, steps 4 and 10, and RFC 7515 section 5.2, step 3: the decoded header and claims set are each
/// verified to be "a UTF-8-encoded representation of a completely valid JSON object". An octet sequence that is not
/// UTF-8 is refused as malformed, however validly it is signed, rather than read with its bad octets replaced.
/// </summary>
public class InvalidUtf8Tests
{
	private static readonly OctetJsonWebKey Key = JsonWebKeyFactory.CreateHmac(SigningAlgorithms.HS256);

	private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

	private static IServiceProvider CreateServiceProvider()
	{
		var services = new ServiceCollection();
		services.AddSingleton(TimeProvider.System);
		services.AddLogging();
		services.AddJsonWebTokens();
		return services.BuildServiceProvider();
	}

	private const string Header = """{"alg":"HS256","typ":"JWT","x":"#"}""";
	private const string Payload = """{"iss":"test-issuer","aud":"test-audience","sub":"#"}""";

	[Fact]
	public async Task ASignedTokenInUtf8_Validates()
	{
		var result = await ValidateAsync(Signed(Utf8(Header, "a"), Utf8(Payload, "a")));

		Assert.True(result.TryGetSuccess(out var token));
		Assert.Equal("a", token.Payload.Subject);
	}

	[Fact]
	public async Task AHeaderThatIsNotUtf8_IsMalformed()
	{
		var result = await ValidateAsync(Signed(NotUtf8(Header), Utf8(Payload, "a")));

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.MalformedToken, error.Error);
	}

	[Fact]
	public async Task AClaimsSetThatIsNotUtf8_IsMalformed()
	{
		var result = await ValidateAsync(Signed(Utf8(Header, "a"), NotUtf8(Payload)));

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.MalformedToken, error.Error);
	}

	/// <summary>
	/// RFC 7516 section 5.2, step 3: the decoded protected header of a JWE is held to the same rule, and is refused
	/// before any key is tried.
	/// </summary>
	[Fact]
	public async Task AJweHeaderThatIsNotUtf8_IsRefusedBeforeAnyKey()
	{
		var encryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
		var token = new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.HS256 },
			Payload = { Issuer = "test-issuer", Audiences = ["test-audience"] },
		};
		var parts = (await ServiceProvider.GetRequiredService<IJsonWebTokenCreator>()
			.IssueAsync(token, Key, encryptionKey)).Split('.');
		parts[0] = Base64Url.EncodeToString(NotUtf8("""{"alg":"RSA-OAEP-256","enc":"A256CBC-HS512","x":"#"}"""));
		var keysRead = 0;

		var result = await ServiceProvider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(
			string.Join('.', parts),
			new ValidationParameters
			{
				TokenTypes = TokenTypePolicy.CheckedByCaller,
				ResolveIssuerSigningKeys = _ => new JsonWebKey[] { Key }.ToAsyncEnumerable(),
				ResolveTokenDecryptionKeys = _ => new JsonWebKey[] { encryptionKey }.ToAsyncEnumerable().Select(key =>
				{
					keysRead++;
					return key;
				}),
			});

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidToken, error.Error);
		Assert.Equal(0, keysRead);
	}

	/// <summary>
	/// A string escaping half of a surrogate pair is no Unicode text either, though its octets are UTF-8, and is
	/// refused where the token arrives.
	/// </summary>
	[Theory]
	[InlineData("""{"alg":"HS256","typ":"JWT","kid":"\udc00"}""", Payload)]
	[InlineData(Header, """{"iss":"\ud800","aud":"test-audience","sub":"a"}""")]
	[InlineData(Header, """{"iss":"test-issuer","aud":"test-audience","sub":"\ud800"}""")]
	[InlineData(Header, """{"iss":"test-issuer","aud":"test-audience","sub":"a","\ud800":1}""")]
	public async Task ALoneSurrogateEscape_IsMalformed(string header, string payload)
	{
		var result = await ValidateAsync(Signed(Utf8(header, "a"), Utf8(payload, "a")));

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.MalformedToken, error.Error);
	}

	private static byte[] Utf8(string json, string value) => Encoding.UTF8.GetBytes(json.Replace("#", value));

	/// <summary>The JSON with a lone 0xFF octet, which no UTF-8 sequence contains, inside a string value.</summary>
	private static byte[] NotUtf8(string json)
	{
		var bytes = Encoding.UTF8.GetBytes(json);
		bytes[Array.IndexOf(bytes, (byte)'#')] = 0xFF;
		return bytes;
	}

	private static string Signed(byte[] header, byte[] payload)
	{
		var signingInput = $"{Base64Url.EncodeToString(header)}.{Base64Url.EncodeToString(payload)}";
		var signature = HMACSHA256.HashData(Key.KeyValue!, Encoding.ASCII.GetBytes(signingInput));
		return $"{signingInput}.{Base64Url.EncodeToString(signature)}";
	}

	private static Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(string jwt)
		=> ServiceProvider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(jwt, new ValidationParameters
		{
			TokenTypes = TokenTypePolicy.CheckedByCaller,
			Options = ValidationOptions.RequireSignedTokens,
			AllowedSigningAlgorithms = new HashSet<string> { SigningAlgorithms.HS256 },
			ResolveIssuerSigningKeys = _ => new JsonWebKey[] { Key }.ToAsyncEnumerable(),
		});
}
