// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// A verification key arrives from somebody else's JWK Set, so key material the platform cannot import is a key the
/// signature does not verify under: the token gets a validation result, and a sibling key of the same set still
/// verifies it.
/// </summary>
public class UnimportableSigningKeyTests
{
	private const string KeyId = "shared-kid";

	private static readonly IServiceProvider ServiceProvider = CreateServiceProvider();

	private static IServiceProvider CreateServiceProvider()
	{
		var services = new ServiceCollection();
		services.AddSingleton(TimeProvider.System);
		services.AddLogging();
		services.AddJsonWebTokens();
		return services.BuildServiceProvider();
	}

	public static TheoryData<string, string> UnimportableKeys => new()
	{
		{ SigningAlgorithms.ES256, "unsupported curve" },
		{ SigningAlgorithms.ES256, "point off the curve" },
		{ SigningAlgorithms.ES256, "coordinate of the wrong length" },
		{ SigningAlgorithms.ES256, "missing y" },
		{ SigningAlgorithms.ES256, "private key of the wrong length" },
		{ SigningAlgorithms.RS256, "missing exponent" },
		{ SigningAlgorithms.RS256, "private exponent without the primes" },
		{ SigningAlgorithms.RS256, "modulus beyond what the platform imports" },
	};

	[Theory]
	[MemberData(nameof(UnimportableKeys))]
	public async Task AnUnimportableKey_DoesNotVerify(string algorithm, string defect)
	{
		var (signingKey, _) = KeysFor(algorithm);
		var jwt = await IssueAsync(algorithm, signingKey);

		var result = await ValidateAsync(jwt, Unimportable(algorithm, defect));

		Assert.True(result.TryGetFailure(out var error));
		Assert.Equal(JwtError.InvalidSignature, error.Error);
	}

	[Theory]
	[MemberData(nameof(UnimportableKeys))]
	public async Task AnUnimportableKey_LeavesItsSiblingToVerify(string algorithm, string defect)
	{
		var (signingKey, publicKey) = KeysFor(algorithm);
		var jwt = await IssueAsync(algorithm, signingKey);

		var result = await ValidateAsync(jwt, Unimportable(algorithm, defect), publicKey);

		Assert.True(result.TryGetSuccess(out _));
	}

	[Fact]
	public async Task AnUnimportableKey_IsRecordedOnce()
	{
		var logger = new RecordingLogger<KeyedSignatureCheck>();
		var services = new ServiceCollection();
		services.AddSingleton(TimeProvider.System);
		services.AddLogging();
		services.AddJsonWebTokens();
		services.AddSingleton<ILogger<KeyedSignatureCheck>>(logger);
		var provider = services.BuildServiceProvider();
		var (signingKey, publicKey) = KeysFor(SigningAlgorithms.ES256);
		var jwt = await IssueAsync(SigningAlgorithms.ES256, signingKey);

		await provider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(jwt, new ValidationParameters
		{
			TokenTypes = TokenTypePolicy.CheckedByCaller,
			Options = ValidationOptions.RequireSignedTokens,
			ResolveIssuerSigningKeys = _ => new[] { Unimportable(SigningAlgorithms.ES256, "point off the curve"), publicKey }
				.ToAsyncEnumerable(),
		});

		var entry = Assert.Single(logger.Entries);
		Assert.Equal(LogEvents.Jwt.UnimportableKey, entry.EventId);
	}

	private static (JsonWebKey SigningKey, JsonWebKey PublicKey) KeysFor(string algorithm)
	{
		JsonWebKey signingKey = algorithm switch
		{
			SigningAlgorithms.ES256 => JsonWebKeyFactory.CreateEllipticCurve(EllipticCurveTypes.P256, algorithm),
			SigningAlgorithms.RS256 => JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, algorithm),
			_ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null),
		};
		signingKey.KeyId = KeyId;
		return (signingKey, signingKey.Sanitize(includePrivateKeys: false));
	}

	private static JsonWebKey Unimportable(string algorithm, string defect)
	{
		var (_, publicKey) = KeysFor(algorithm);
		return (publicKey, defect) switch
		{
			(EllipticCurveJsonWebKey ec, "unsupported curve") => ec with { Curve = "secp256k1" },
			(EllipticCurveJsonWebKey ec, "point off the curve") => ec with { Y = Flipped(ec.Y!) },
			(EllipticCurveJsonWebKey ec, "coordinate of the wrong length") => ec with { X = ec.X![1..] },
			(EllipticCurveJsonWebKey ec, "missing y") => ec with { Y = null },
			(EllipticCurveJsonWebKey ec, "private key of the wrong length") => ec with { PrivateKey = [1, 2, 3] },
			(RsaJsonWebKey rsa, "missing exponent") => rsa with { Exponent = null },
			(RsaJsonWebKey rsa, "private exponent without the primes") => rsa with { PrivateExponent = rsa.Modulus },
			(RsaJsonWebKey rsa, "modulus beyond what the platform imports") => rsa with
			{
				Modulus = [0xFF, .. CryptoRandom.GetRandomBytes(64 * 1024)],
			},
			_ => throw new ArgumentOutOfRangeException(nameof(defect), defect, null),
		};
	}

	private static byte[] Flipped(byte[] coordinate)
	{
		var copy = (byte[])coordinate.Clone();
		copy[^1] ^= 1;
		return copy;
	}

	private static async Task<string> IssueAsync(string algorithm, JsonWebKey signingKey)
	{
		var token = new JsonWebToken
		{
			Header = { Algorithm = algorithm },
			Payload = { Issuer = "test-issuer", Audiences = ["test-audience"] },
		};
		return await ServiceProvider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, signingKey);
	}

	private static Task<Result<JsonWebToken, JwtValidationError>> ValidateAsync(string jwt, params JsonWebKey[] keys)
		=> ServiceProvider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(jwt, new ValidationParameters
		{
			TokenTypes = TokenTypePolicy.CheckedByCaller,
			Options = ValidationOptions.RequireSignedTokens,
			ResolveIssuerSigningKeys = _ => keys.ToAsyncEnumerable(),
		});
}
