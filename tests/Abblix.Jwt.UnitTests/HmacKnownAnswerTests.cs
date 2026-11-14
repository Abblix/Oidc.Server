// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Text;
using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The HS256 example of RFC 7515 Appendix A.1, an answer computed outside this library: the listed key signs the
/// listed signing input to the listed signature, and the validator accepts the listed JWS.
/// </summary>
public class HmacKnownAnswerTests
{
	private const string EncodedHeader = "eyJ0eXAiOiJKV1QiLA0KICJhbGciOiJIUzI1NiJ9";

	private const string EncodedPayload =
		"eyJpc3MiOiJqb2UiLA0KICJleHAiOjEzMDA4MTkzODAsDQogImh0dHA6Ly9leGFtcGxlLmNvbS9pc19yb290Ijp0cnVlfQ";

	private const string EncodedSignature = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";

	private static readonly OctetJsonWebKey Key = new()
	{
		KeyValue = Base64Url.DecodeFromChars("AyM1SysPpbyDfgZld3umj1qzKObwVMkoqQ-EstJQLr_T-1qS0gZH75aKtMN3Yj0iPS4hcgUuTwjAzZr1Z9CAow"),
	};

	[Fact]
	public void TheListedKey_SignsTheListedInputToTheListedSignature()
	{
		var signature = new HmacSigner(SigningAlgorithms.HS256)
			.Sign(Key, Encoding.ASCII.GetBytes($"{EncodedHeader}.{EncodedPayload}"));

		Assert.Equal(EncodedSignature, Base64Url.EncodeToString(signature));
	}

	[Fact]
	public async Task TheListedJws_Validates()
	{
		var services = new ServiceCollection();
		services.AddSingleton(TimeProvider.System);
		services.AddLogging();
		services.AddJsonWebTokens();
		var validator = services.BuildServiceProvider().GetRequiredService<IJsonWebTokenValidator>();

		var result = await validator.ValidateAsync(
			$"{EncodedHeader}.{EncodedPayload}.{EncodedSignature}",
			new ValidationParameters
			{
				TokenTypes = TokenTypePolicy.CheckedByCaller,
				// The example expired in 2011; its lifetime is not what it pins
				Options = ValidationOptions.RequireSignedTokens,
				AllowedSigningAlgorithms = new HashSet<string> { SigningAlgorithms.HS256 },
				ResolveIssuerSigningKeys = _ => new JsonWebKey[] { Key }.ToAsyncEnumerable(),
			});

		Assert.True(result.TryGetSuccess(out var token));
		Assert.Equal("joe", token.Payload.Issuer);
	}
}
