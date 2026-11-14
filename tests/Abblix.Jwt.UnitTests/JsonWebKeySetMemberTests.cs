// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text;
using System.Text.Json;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// RFC 7517 section 5: "Implementations SHOULD ignore JWKs within a JWK Set that use "kty" (key type) values that are
/// not understood by them, that are missing required members, or for which values are out of the supported ranges."
/// An issuer's set holding such a key still verifies a token under its other keys.
/// </summary>
public class JsonWebKeySetMemberTests
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

	[Theory]
	[InlineData("""{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}""")]
	[InlineData("""{"kty":"RSA","n":"!!!","e":"AQAB"}""")]
	[InlineData("""{"kty":"RSA","e":"AQAB"}""")]
	[InlineData("""{"kty":"EC","crv":"P-256","x":{},"y":"AQAB"}""")]
	[InlineData("""{"kty":"EC","crv":"P-256","x":"AQAB"}""")]
	[InlineData("""{"kty":"EC","crv":"secp256k1","x":"AQAB","y":"AQAB"}""")]
	[InlineData("""{"kty":"oct","kid":"a","kid":"b","k":"AQID"}""")]
	[InlineData("""{"kid":"no-type"}""")]
	[InlineData("""5""")]
	[InlineData("""null""")]
	public async Task AKeySetMemberNotUnderstood_IsIgnored_AndTheOthersStillVerify(string member)
	{
		var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
		var publicKey = JsonSerializer.Serialize(signingKey.Sanitize(includePrivateKeys: false));
		var set = JsonSerializer.Deserialize<JsonWebKeySet>($$"""{"keys":[{{member}},{{publicKey}}]}""")!;

		var token = new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.RS256 },
			Payload = { Issuer = "test-issuer", Audiences = ["test-audience"] },
		};
		var jwt = await ServiceProvider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, signingKey);

		var result = await ServiceProvider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(
			jwt,
			new ValidationParameters
			{
				TokenTypes = TokenTypePolicy.CheckedByCaller,
				Options = ValidationOptions.RequireSignedTokens,
				ResolveIssuerSigningKeys = _ => set.Keys.ToAsyncEnumerable(),
			});

		Assert.Equal(signingKey.KeyId, Assert.Single(set.Keys).KeyId);
		Assert.True(result.TryGetSuccess(out _));
	}

	/// <summary>
	/// A key holding a string that is not Unicode text (octets that are not UTF-8, or an escaped lone surrogate), even
	/// in a member the library does not read, is not a JWK it understands, and is left out of the set as one.
	/// </summary>
	[Theory]
	[InlineData("""{"kty":"oct","k":"AAAA","zz":"#"}""")]
	[InlineData("""{"kty":"oct","k":"AAAA","key_ops":["#"]}""")]
	[InlineData("""{"kty":"oct","k":"AAAA","zz":{"zz":"#"}}""")]
	[InlineData("""{"kty":"oct","k":"AAAA","zz":"\ud800"}""")]
	public async Task AKeySetMemberThatIsNotUnicodeText_IsIgnored(string member)
	{
		var publicKey = JsonSerializer.Serialize(
			JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature).Sanitize(includePrivateKeys: false));
		var octets = Encoding.UTF8.GetBytes($$"""{"keys":[{{member}},{{publicKey}}]}""");
		var marker = Array.IndexOf(octets, (byte)'#');
		if (marker >= 0)
			octets[marker] = 0xFF;

		using var stream = new MemoryStream(octets);
		var set = await JsonSerializer.DeserializeAsync<JsonWebKeySet>(
			stream, cancellationToken: TestContext.Current.CancellationToken);

		Assert.IsType<RsaJsonWebKey>(Assert.Single(set!.Keys));
	}

	/// <summary>
	/// A single key is read on its own, with nothing to fall back on, so one not understood is still refused.
	/// </summary>
	[Theory]
	[InlineData("""{"kty":"OKP","crv":"Ed25519","x":"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo"}""")]
	[InlineData("""{"kty":"RSA","n":"!!!","e":"AQAB"}""")]
	public void ASingleKeyNotUnderstood_IsStillRefused(string json)
	{
		Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<JsonWebKey>(json));
	}

	/// <summary>
	/// The set itself is still held to its format: a keys member that is not an array is not a JWK Set.
	/// </summary>
	[Theory]
	[InlineData("""{"keys":{"kty":"oct","k":"AQID"}}""")]
	[InlineData("""{"keys":"none"}""")]
	public void AKeysMemberThatIsNotAnArray_IsRefused(string json)
	{
		Assert.Throws<JsonException>(() => JsonSerializer.Deserialize<JsonWebKeySet>(json));
	}
}
