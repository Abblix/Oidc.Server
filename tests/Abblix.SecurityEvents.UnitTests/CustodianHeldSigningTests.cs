// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Runtime.CompilerServices;
using System.Security.Cryptography;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// A transmitter that signs Security Event Tokens with a key it does not hold. This project references
/// Abblix.SecurityEvents and, through it, Abblix.Jwt - and nothing else, which is exactly the dependency graph of
/// a transmitter that is not an OpenID Provider. If the placement wiring needed the OIDC server, none of this
/// would compile.
/// </summary>
/// <remarks>
/// The signature is the assertion. The host is handed only the PUBLIC half, and the composed signing seam reads
/// that absence of private material as the instruction to route the signature to the custodian by <c>kid</c>. So a
/// token that validates against the public key can only have been produced by the custodian's private half, which
/// never entered the container.
/// </remarks>
public class CustodianHeldSigningTests
{
    private const string Issuer = "https://transmitter.example.com";
    private const string Audience = "https://receiver.example.com/events";
    private const string SessionRevoked = "https://transmitter.example.com/events/session-revoked";
    private const string SigningKeyName = "set-signing";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    [Fact]
    public async Task ATransmitterSignsThroughTheCustodian_WithNoOidcServerInSight()
    {
        using var rsa = RSA.Create(2048);
        var custodian = new RsaCustodian(rsa, SigningKeyName);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.AddSingleton<IKeyCustodian>(custodian);

        // Deferred so the key source reads the container rather than this method's locals. That is not a
        // formality: reading CustodianHeldKeys back is the only thing that proves the placement REGISTERED the
        // selection, and a lambda closing over the literals would pass with that registration deleted.
        IServiceProvider? resolved = null;

        services.AddSecurityEvents(options => options.SigningKeySource = async cancellationToken =>
        {
            var provider = resolved!;

            // What a transmitter does with the placement: ask which keys it named, then ask the custodian for that
            // key's versions and hand on the public half. Everything used here is public in Abblix.Jwt.
            var chosen = provider.GetRequiredService<CustodianHeldKeys>();
            var keyCustodian = provider.GetRequiredService<IKeyCustodian>();

            var versions = new List<KeyVersion>();
            await foreach (var version in keyCustodian.GetKeyVersionsAsync(chosen.SigningKeyName, cancellationToken))
                versions.Add(version);

            return versions
                .ProduceFirst(version => version.CreatedAt, Now, TimeSpan.FromHours(1))
                .Select(version => version.PublicKey with { Algorithm = chosen.SigningAlgorithm })
                .First();
        });

        // The placement, chosen with nothing but this package's own calls.
        services.RequireKeyPlacement().UseKeysInCustodian(
            new CustodianHeldKeys { SigningKeyName = SigningKeyName });

        var publicHalf = new RsaJsonWebKey { KeyId = SigningKeyName, Algorithm = SigningAlgorithms.RS256 }
            .Apply(rsa.ExportParameters(false));
        services.AddSingleton<IIssuerKeyResolver>(new FixedKeyResolver(publicHalf));

        await using var host = services.BuildServiceProvider();
        resolved = host;

        // Startup validation is satisfied: the guard the custodian registration armed has an answer.
        host.GetRequiredService<IStartupValidator>().Validate();

        var compact = await new SecurityEventTokenBuilder()
            .WithIssuer(Issuer)
            .WithJwtId("jti-custodian-1")
            .WithIssuedAt(Now)
            .WithAudience(Audience)
            .WithEvent(SessionRevoked, new JsonObject { ["reason"] = "operator" })
            .SignAsync(host.GetRequiredService<ISecurityEventTokenSigner>(), TestContext.Current.CancellationToken);

        Assert.Equal(1, custodian.SignatureCount);

        var result = await host.GetRequiredService<ISecurityEventTokenValidator>().ValidateAsync(
            compact,
            new SecurityEventTokenValidationOptions
            {
                ExpectedAudience = Audience,
                ExpectedIssuers = [Issuer],
            },
            TestContext.Current.CancellationToken);

        Assert.False(result.TryGetFailure(out var error), error?.Description);
    }

    /// <summary>
    /// A custodian holding one RSA key: it signs, and it publishes the public half. The private parameters are
    /// never exported, so nothing the container can reach carries them.
    /// </summary>
    private sealed class RsaCustodian(RSA rsa, string signingKeyName) : IKeyCustodian
    {
        public int SignatureCount { get; private set; }

        public Task<byte[]> SignAsync(
            string keyId, string algorithm, byte[] data, CancellationToken cancellationToken)
        {
            Assert.Equal(SigningAlgorithms.RS256, algorithm);
            Assert.Equal(signingKeyName, keyId);
            SignatureCount++;

            return Task.FromResult(rsa.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        public Task<byte[]?> UnwrapKeyAsync(
            string keyId,
            string algorithm,
            JsonWebTokenHeader header,
            byte[] encryptedKey,
            CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public Task<byte[]> AgreeKeyAsync(
            string keyId, string algorithm, JsonWebKey ephemeralPublicKey, CancellationToken cancellationToken)
            => throw new NotSupportedException();

        public async IAsyncEnumerable<KeyVersion> GetKeyVersionsAsync(
            string keyName,
            [EnumeratorCancellation] CancellationToken cancellationToken)
        {
            await Task.Yield();

            yield return new KeyVersion(
                new RsaJsonWebKey { KeyId = keyName }.Apply(rsa.ExportParameters(false)),
                Now.AddDays(-1));
        }
    }

    private sealed class FixedKeyResolver(params JsonWebKey[] keys) : IIssuerKeyResolver
    {
        public async IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
            string issuer,
            string? keyId = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            foreach (var key in keys)
                yield return key;
        }
    }
}
