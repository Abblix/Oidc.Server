// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// The refusal for a token no issuer key can verify goes back to whoever presented the token, so it must read the
/// same whatever the issuer's key ring holds.
/// </summary>
public class NoMatchingKeyDisclosureTests
{
    [Fact]
    public async Task UnknownKid_RefusalDoesNotDependOnTheIssuersKeyCount()
    {
        var header = new JsonObject { ["alg"] = SigningAlgorithms.RS256, ["kid"] = "unknown-kid" };

        var oneKey = await Refuse(header, 1, keyAlgorithm: null);
        var threeKeys = await Refuse(header, 3, keyAlgorithm: null);

        Assert.Equal(JwtError.InvalidToken, oneKey.Error);
        Assert.Equal(oneKey, threeKeys);
    }

    [Fact]
    public async Task NoKid_KeysOfAnotherAlgorithm_RefusalDoesNotDependOnTheIssuersKeyCount()
    {
        var header = new JsonObject { ["alg"] = SigningAlgorithms.RS256 };

        var oneKey = await Refuse(header, 1, SigningAlgorithms.RS384);
        var threeKeys = await Refuse(header, 3, SigningAlgorithms.RS384);

        Assert.Equal(JwtError.InvalidToken, oneKey.Error);
        Assert.Equal(oneKey, threeKeys);
    }

    private static async Task<JwtValidationError> Refuse(JsonObject header, int keyCount, string? keyAlgorithm)
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        var signer = services.BuildServiceProvider().GetRequiredService<IJsonWebTokenSigner>();
        var issuerKeys = Enumerable.Range(0, keyCount)
            .Select(_ => JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, keyAlgorithm))
            .ToArray();

        var error = await signer.ValidateAsync(
            ["header", "payload", "signature"],
            new JsonWebTokenHeader(header),
            issuerKeys.ToAsyncEnumerable(),
            TestContext.Current.CancellationToken);

        return Assert.IsType<JwtValidationError>(error);
    }
}
