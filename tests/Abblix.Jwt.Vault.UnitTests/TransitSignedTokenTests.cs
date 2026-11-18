// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Buffers.Text;
using System.Net;
using System.Security.Cryptography;
using System.Text.Json;
using Abblix.Jwt.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.Jwt.Vault.UnitTests;

/// <summary>
/// A token issued with a Transit-held EC key verifies against the key's public half. Transit answers a sign request
/// with <c>marshaling_algorithm: jws</c> in the encoding its own source uses for that marshaling,
/// <c>base64.RawURLEncoding</c> (unpadded base64url), and keeps padded standard base64 for the default ASN.1
/// marshaling; the stub below answers the same way.
/// </summary>
public sealed class TransitSignedTokenTests : IDisposable
{
    private readonly List<IDisposable> _disposables = [];

    [Theory]
    [InlineData(EllipticCurveTypes.P256, SigningAlgorithms.ES256)]
    [InlineData(EllipticCurveTypes.P384, SigningAlgorithms.ES384)]
    [InlineData(EllipticCurveTypes.P521, SigningAlgorithms.ES512)]
    public async Task AnEcTokenSignedByTransit_Verifies(string curve, string algorithm)
    {
        var fullKey = JsonWebKeyFactory.CreateEllipticCurve(curve, algorithm);
        fullKey.KeyId = "oidc-sign:1";
        var publicKey = fullKey.Sanitize(includePrivateKeys: false);

        using var ecdsa = fullKey.ToEcdsa();
        var hash = algorithm switch
        {
            SigningAlgorithms.ES256 => HashAlgorithmName.SHA256,
            SigningAlgorithms.ES384 => HashAlgorithmName.SHA384,
            SigningAlgorithms.ES512 => HashAlgorithmName.SHA512,
            _ => throw new ArgumentOutOfRangeException(nameof(algorithm), algorithm, null),
        };

        var handler = new StubHttpMessageHandler((_, body) =>
        {
            using var request = JsonDocument.Parse(body);
            var input = Convert.FromBase64String(request.RootElement.GetProperty("input").GetString()!);
            var signature = ecdsa.SignData(input, hash, DSASignatureFormat.IeeeP1363FixedFieldConcatenation);
            return StubHttpMessageHandler.Json(
                HttpStatusCode.OK, new { data = new { signature = $"vault:v1:{Base64Url.EncodeToString(signature)}" } });
        });

        var httpClient = new HttpClient(handler) { BaseAddress = new Uri("https://vault.test/v1/") };
        _disposables.Add(httpClient);
        var custodian = new TransitCustodian(
            NullLogger<TransitCustodian>.Instance,
            new StubHttpClientFactory(httpClient),
            Options.Create(new VaultTransitOptions { TransitMount = "transit" }));

        var services = new ServiceCollection();
        services.AddSingleton(TimeProvider.System);
        services.AddLogging();
        services.AddJsonWebTokens();
        services.AddSingleton<IKeyCustodian>(custodian);
        services.RequireKeyPlacement().UseKeysInCustodian();
        var provider = services.BuildServiceProvider();
        _disposables.Add(provider);

        var token = new JsonWebToken
        {
            Header = { Algorithm = algorithm },
            Payload = { Issuer = "https://issuer.example.com", Audiences = ["test-audience"] },
        };

        var jwt = await provider.GetRequiredService<IJsonWebTokenCreator>().IssueAsync(token, publicKey);

        var result = await provider.GetRequiredService<IJsonWebTokenValidator>().ValidateAsync(jwt, new ValidationParameters
        {
            TokenTypes = TokenTypePolicy.CheckedByCaller,
            Options = ValidationOptions.RequireSignedTokens,
            ResolveIssuerSigningKeys = _ => new[] { publicKey }.ToAsyncEnumerable(),
        });

        Assert.True(result.TryGetSuccess(out _));
    }

    public void Dispose()
    {
        foreach (var disposable in _disposables)
            disposable.Dispose();
    }
}
