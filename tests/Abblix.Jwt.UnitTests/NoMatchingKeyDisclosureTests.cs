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
    public async Task NoKeyMatches_RefusalDoesNotDependOnTheIssuersKeyCount()
    {
        var oneKey = await RefuseUnknownKid(1);
        var threeKeys = await RefuseUnknownKid(3);

        Assert.Equal(JwtError.InvalidToken, oneKey.Error);
        Assert.Equal(oneKey.Error, threeKeys.Error);
        Assert.Equal(oneKey.ErrorDescription, threeKeys.ErrorDescription);
    }

    private static async Task<JwtValidationError> RefuseUnknownKid(int keyCount)
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        var signer = services.BuildServiceProvider().GetRequiredService<IJsonWebTokenSigner>();
        var header = new JsonWebTokenHeader(new JsonObject
        {
            ["alg"] = SigningAlgorithms.RS256,
            ["kid"] = "unknown-kid",
        });
        var issuerKeys = Enumerable.Range(0, keyCount)
            .Select(_ => JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature))
            .ToArray();

        var error = await signer.ValidateAsync(
            ["header", "payload", "signature"],
            header,
            issuerKeys.ToAsyncEnumerable(),
            TestContext.Current.CancellationToken);

        return Assert.IsType<JwtValidationError>(error);
    }
}
