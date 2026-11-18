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
/// RFC 7519 section 5.2: "In the case that nested signing or encryption is employed, this Header Parameter MUST be
/// present; in this case, the value MUST be "JWT", to indicate that a Nested JWT is carried in this JWT." In the
/// normal case its use is "NOT RECOMMENDED", so a token that is only signed carries none.
/// </summary>
public class NestedJwtContentTypeTests
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
	private static readonly JsonWebKey EncryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);

	[Fact]
	public async Task ASignedAndEncryptedToken_NamesItsContentAJwt_AndValidates()
	{
		var jwe = await IssueAsync(EncryptionKey);

		Assert.Equal(JsonWebTokenTypes.Jwt, HeaderOf(jwe)[JwtClaimTypes.ContentType]?.GetValue<string>());

		var result = await ServiceProvider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(
			jwe,
			new ValidationParameters
			{
				TokenTypes = TokenTypePolicy.CheckedByCaller,
				Options = ValidationOptions.RequireSignedTokens,
				ResolveIssuerSigningKeys = _ => SigningKey.ToAsync(),
				ResolveTokenDecryptionKeys = _ => EncryptionKey.ToAsync(),
			});
		Assert.True(result.TryGetSuccess(out _));
	}

	[Fact]
	public async Task ATokenOnlySigned_CarriesNoContentType()
	{
		var jws = await IssueAsync(encryptionKey: null);

		Assert.False(HeaderOf(jws).ContainsKey(JwtClaimTypes.ContentType));
	}

	private static Task<string> IssueAsync(JsonWebKey? encryptionKey)
	{
		var token = new JsonWebToken
		{
			Header = { Algorithm = SigningAlgorithms.RS256 },
			Payload = { Issuer = "test-issuer", Audiences = ["test-audience"] },
		};
		return ServiceProvider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, SigningKey, encryptionKey);
	}

	private static JsonObject HeaderOf(string jwt)
		=> JsonNode.Parse(Base64Url.DecodeFromChars(jwt.Split('.')[0]))!.AsObject();
}
