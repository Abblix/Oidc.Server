// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Jwt.UnitTests;

/// <summary>
/// <see cref="ValidationParameters.ValidateKeyManagementAlgorithm"/> judges the key management algorithm of every JWE
/// layer before that layer is decrypted, so a caller can refuse one, RSA1_5 under FAPI 1.0 Part 2 section 8.6.1, wherever
/// in the token it sits.
/// </summary>
public class KeyManagementAlgorithmPolicyTests
{
    private static readonly JsonWebKey SigningKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature);
    private static readonly JsonWebKey EncryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);

    private static readonly IServiceProvider Services = CreateServices();

    private static IServiceProvider CreateServices()
    {
        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddRsaPkcs1KeyManagement();
        return services.BuildServiceProvider();
    }

    private static JsonWebToken Token()
    {
        var now = TimeProvider.System.GetUtcNow();
        return new JsonWebToken
        {
            Header = { Algorithm = SigningAlgorithms.PS256 },
            Payload = { Issuer = "issuer", Audiences = ["audience"], IssuedAt = now, NotBefore = now, ExpiresAt = now.AddMinutes(5) },
        };
    }

    private static Task<Result<JsonWebToken, JwtValidationError>> Validate(string jwt, List<string> seen)
        => Services.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(jwt, new ValidationParameters
        {
            TokenTypes = TokenTypePolicy.CheckedByCaller,
            ValidateAudience = _ => Task.FromResult(true),
            ValidateIssuer = _ => Task.FromResult(true),
            ResolveIssuerSigningKeys = _ => SigningKey.ToAsync(),
            ResolveTokenDecryptionKeys = _ => EncryptionKey.ToAsync(),
            ValidateKeyManagementAlgorithm = algorithm =>
            {
                seen.Add(algorithm);
                return algorithm != EncryptionAlgorithms.KeyManagement.Rsa1_5;
            },
        });

    /// <summary>
    /// A token encrypted with an admitted algorithm is opened, its algorithm judged once.
    /// </summary>
    [Fact]
    public async Task AnAdmittedAlgorithm_IsOpened()
    {
        var jwe = await Services.GetRequiredService<IJsonWebTokenCreator>()
            .IssueAsync(Token(), SigningKey, EncryptionKey, EncryptionAlgorithms.KeyManagement.RsaOaep256);
        var seen = new List<string>();

        Assert.True((await Validate(jwe, seen)).TryGetSuccess(out _));
        Assert.Equal([EncryptionAlgorithms.KeyManagement.RsaOaep256], seen);
    }

    /// <summary>
    /// A token encrypted with a refused algorithm is refused.
    /// </summary>
    [Fact]
    public async Task ARefusedAlgorithm_IsRefused()
    {
        var jwe = await Services.GetRequiredService<IJsonWebTokenCreator>()
            .IssueAsync(Token(), SigningKey, EncryptionKey, EncryptionAlgorithms.KeyManagement.Rsa1_5);

        var seen = new List<string>();

        Assert.True((await Validate(jwe, seen)).TryGetFailure(out var error));
        Assert.Equal(JwtError.InvalidToken, error.Error);
        Assert.Equal([EncryptionAlgorithms.KeyManagement.Rsa1_5], seen);
    }

    /// <summary>
    /// A refused algorithm under an admitted one is refused too: a JWE wrapped in another is judged layer by layer.
    /// </summary>
    [Fact]
    public async Task ARefusedAlgorithmInsideAnAdmittedOne_IsRefused()
    {
        var inner = await Services.GetRequiredService<IJsonWebTokenCreator>()
            .IssueAsync(Token(), SigningKey, EncryptionKey, EncryptionAlgorithms.KeyManagement.Rsa1_5);
        var outer = await Services.GetRequiredService<IJsonWebTokenEncryptor>().EncryptAsync(
            Encoding.UTF8.GetBytes(inner),
            EncryptionKey,
            tokenType: null,
            EncryptionAlgorithms.KeyManagement.RsaOaep256,
            EncryptionAlgorithms.ContentEncryption.Aes256CbcHmacSha512,
            TestContext.Current.CancellationToken);
        var seen = new List<string>();

        Assert.True((await Validate(outer, seen)).TryGetFailure(out _));
        Assert.Equal([EncryptionAlgorithms.KeyManagement.RsaOaep256, EncryptionAlgorithms.KeyManagement.Rsa1_5], seen);
    }
}
