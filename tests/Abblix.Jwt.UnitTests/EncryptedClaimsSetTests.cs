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
		return ServiceProvider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, null, EncryptionKey);
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
}
