// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text.Json.Nodes;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// A JWT encrypted without being signed. RFC 7519 section 3: "If the JOSE Header is for a JWE, the JWT is represented
/// as a JWE and the claims are encrypted, with the JWT Claims Set being the plaintext encrypted by the JWE"; Appendix
/// A.1 uses "the octets of the UTF-8 representation of the JWT Claims Set ... as the plaintext value". Only a nested
/// JWT carries cty JWT (section 5.2), and section 7.2 step 8 reads the plaintext as a JWT only then.
/// </summary>
public class EncryptedClaimsSetTests
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

	private static readonly JsonWebKey EncryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);

	private static Task<string> IssueUnsignedAsync()
	{
		var token = new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.None },
			Payload = { Issuer = "test-issuer", Audiences = ["test-audience"], Subject = "user-1" },
		};
		return ServiceProvider.GetRequiredService<IJsonWebTokenCreator>().EncryptClaimsAsync(
			token,
			EncryptionKey,
			EncryptionAlgorithms.KeyManagement.RsaOaep256,
			EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256);
	}

	private static ValidationParameters Parameters(ValidationOptions options) => new()
	{
		TokenTypes = TokenTypePolicy.CheckedByCaller,
		Options = options,
		ResolveTokenDecryptionKeys = _ => EncryptionKey.ToAsync(),
	};

	/// <summary>
	/// The plaintext of a JWT encrypted without a signing key is the claims set itself, and the JWE carries no cty.
	/// </summary>
	[Fact]
	public async Task AnUnsignedEncryptedToken_EncryptsTheClaimsSet()
	{
		var jwe = await IssueUnsignedAsync();

		var header = JsonNode.Parse(Base64Url.DecodeFromChars(jwe.Split('.')[0]))!.AsObject();
		Assert.False(header.ContainsKey(JwtClaimTypes.ContentType));

		var plaintext = await ServiceProvider.GetRequiredService<IJsonWebTokenEncryptor>()
			.DecryptAsync(jwe.Split('.'), EncryptionKey.ToAsync(), TestContext.Current.CancellationToken);
		Assert.True(plaintext.TryGetSuccess(out var bytes));
		var claims = JsonNode.Parse(bytes)!.AsObject();
		Assert.Equal("user-1", claims[JwtClaimTypes.Subject]!.GetValue<string>());
	}

	/// <summary>
	/// A token issued with no signing key and an encryption key stays a nested JWT, an unsigned JWS under cty JWT:
	/// OpenID Connect Core 1.0 section 2 has an encrypted ID token "signed then encrypted, with the result being a Nested
	/// JWT", and the claims-set form is asked for by name.
	/// </summary>
	[Fact]
	public async Task ATokenWithNoSigningKey_StaysANestedJwt()
	{
		var token = new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.None },
			Payload = { Issuer = "test-issuer", Subject = "user-1" },
		};
		var jwe = await ServiceProvider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, null, EncryptionKey);

		var header = JsonNode.Parse(Base64Url.DecodeFromChars(jwe.Split('.')[0]))!.AsObject();
		Assert.Equal(JsonWebTokenTypes.Jwt, header[JwtClaimTypes.ContentType]?.GetValue<string>());
	}

	/// <summary>
	/// A claims set is an unsigned token to every check that reads the algorithm: it validates with the algorithm
	/// none, so a caller refusing unsigned tokens by that name refuses it, and an allow-list without none refuses it.
	/// </summary>
	[Fact]
	public async Task AnUnsignedEncryptedToken_ReadsAsSignedWithNone()
	{
		var jwe = await IssueUnsignedAsync();
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();

		var opened = await validator.ValidateAsync(jwe, Parameters(default));
		Assert.True(opened.TryGetSuccess(out var token));
		Assert.Equal(SigningAlgorithms.None, token.Header.Algorithm);

		var allowList = Parameters(default) with
		{
			AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal) { SigningAlgorithms.RS256 },
		};
		var refused = await validator.ValidateAsync(jwe, allowList);
		Assert.True(refused.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidAlgorithm, error.Error);
	}

	/// <summary>
	/// This library's validator opens such a token and reads its claims where signatures are not required, and
	/// refuses it as unsigned where they are.
	/// </summary>
	[Fact]
	public async Task AnUnsignedEncryptedToken_IsReadUnlessSignaturesAreRequired()
	{
		var jwe = await IssueUnsignedAsync();
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();

		var opened = await validator.ValidateAsync(jwe, Parameters(default));
		Assert.True(opened.TryGetSuccess(out var token));
		Assert.Equal("user-1", token.Payload.Subject);

		var refused = await validator.ValidateAsync(jwe, Parameters(ValidationOptions.RequireSignedTokens));
		Assert.True(refused.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidAlgorithm, error.Error);
	}

	/// <summary>
	/// A JWE whose plaintext is <paramref name="claims"/>, encrypted under <paramref name="tokenType"/> and
	/// <paramref name="contentType"/>, as another party may send it.
	/// </summary>
	private static Task<string> EncryptAsync(JsonObject claims, string? tokenType, string? contentType)
		=> ServiceProvider.GetRequiredService<IJsonWebTokenEncryptor>().EncryptAsync(
			System.Text.Encoding.UTF8.GetBytes(claims.ToJsonString()),
			EncryptionKey,
			tokenType,
			contentType,
			EncryptionAlgorithms.KeyManagement.RsaOaep256,
			EncryptionAlgorithms.ContentEncryption.Aes128CbcHmacSha256,
			TestContext.Current.CancellationToken);

	private static JsonObject Claims() => new()
	{
		[JwtClaimTypes.Issuer] = "test-issuer",
		[JwtClaimTypes.Subject] = "user-1",
	};

	/// <summary>
	/// RFC 7519 section 7.2 step 8: under cty JWT the plaintext "is a JWT that was the subject of nested signing or
	/// encryption operations", in any case of the media type name (section 5.2: "media type names are not case
	/// sensitive"), so a JSON object there is a malformed nested JWT rather than a claims set.
	/// </summary>
	[Theory]
	[InlineData(JsonWebTokenTypes.Jwt)]
	[InlineData("jwt")]
	public async Task AJsonObjectUnderCtyJwt_IsAMalformedNestedJwt(string contentType)
	{
		var jwe = await EncryptAsync(Claims(), tokenType: null, contentType);

		var result = await ServiceProvider.GetRequiredService<IJsonWebTokenValidator>()
			.ValidateAsync(jwe, Parameters(default));

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.MalformedToken, error.Error);
	}

	/// <summary>
	/// The claims set takes the JWE's typ, so a validation requiring a type refuses one whose JWE names none or
	/// another, and accepts the matching one.
	/// </summary>
	[Theory]
	[InlineData(null, false)]
	[InlineData(JsonWebTokenTypes.Jwt, false)]
	[InlineData("at+jwt", true)]
	public async Task TheJweTyp_IsTheTypeOfTheClaimsSet(string? tokenType, bool accepted)
	{
		var jwe = await EncryptAsync(Claims(), tokenType, contentType: null);

		var result = await ServiceProvider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(
			jwe,
			Parameters(default) with { TokenTypes = TokenTypePolicy.Exactly("at+jwt") });

		if (accepted)
		{
			Assert.True(result.TryGetSuccess(out _));
		}
		else
		{
			Assert.True(result.TryGetFailure(out var error));
			Assert.Equal(JwtError.InvalidTokenType, error.Error);
		}
	}

	/// <summary>
	/// The claims of a claims set are validated as those of a JWS are: an issuer the caller does not accept and an
	/// expired token are refused.
	/// </summary>
	[Theory]
	[InlineData("issuer")]
	[InlineData("lifetime")]
	public async Task TheClaimsOfAClaimsSet_AreValidated(string check)
	{
		var claims = Claims();
		ValidationParameters parameters;
		switch (check)
		{
			case "issuer":
				parameters = Parameters(ValidationOptions.ValidateIssuer) with
				{
					ValidateIssuer = issuer => Task.FromResult(issuer == "another-issuer"),
				};
				break;

			case "lifetime":
				claims[JwtClaimTypes.ExpiresAt] = TimeProvider.System.GetUtcNow().AddHours(-1).ToUnixTimeSeconds();
				parameters = Parameters(ValidationOptions.ValidateLifetime);
				break;

			default:
				throw new ArgumentOutOfRangeException(nameof(check), check, null);
		}

		var jwe = await EncryptAsync(claims, tokenType: null, contentType: null);
		var validator = ServiceProvider.GetRequiredService<IJsonWebTokenValidator>();

		Assert.True((await validator.ValidateAsync(jwe, Parameters(default))).TryGetSuccess(out _));
		Assert.True((await validator.ValidateAsync(jwe, parameters)).TryGetFailure(out _));
	}
}
