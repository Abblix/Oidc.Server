// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Runtime.CompilerServices;
using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Infrastructure;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// What a deployment will sign a security event token with, and accept one under, stated in one place
/// and enforced on both sides.
/// </summary>
/// <remarks>
/// Before this, neither side said anything: the transmitter signed with whatever the configured key
/// declared, and the receiver accepted whatever the validator's default permitted. Two policies nobody
/// wrote, free to disagree, with no place that would say so.
/// </remarks>
public class SigningAlgorithmPolicyTests
{
    private const string Issuer = "https://tenant.example.com";
    private const string Audience = "https://receiver.example.com/ssf/events";

    private const string SomeEvent = "https://tenant.example.com/events/something-happened";

    /// <summary>The smallest payload a SET can carry: RFC 8417 requires the events object to be there.</summary>
    private sealed class SomethingHappened : IEventPayload;

    private sealed class FixedKeyResolver(params JsonWebKey[] keys) : IIssuerKeyResolver
    {
        public async IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
            string issuer,
            string? keyId = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            foreach (var key in keys)
            {
                yield return key;
            }
        }
    }

    /// <summary>
    /// Every algorithm a deployment allows signs and verifies, end to end.
    /// </summary>
    /// <remarks>
    /// The row RS256 alone would not write: the default is RS256, so a policy that silently ignored the
    /// configured set would still pass a round trip on it. PS256 and ES256 are what this library can
    /// offer of the FAPI 2.0 set; EdDSA it does not implement at all, which is why the option's
    /// documentation names the two rather than the three.
    /// </remarks>
    [Theory]
    [InlineData(SigningAlgorithms.RS256)]
    [InlineData(SigningAlgorithms.PS256)]
    [InlineData(SigningAlgorithms.ES256)]
    public async Task AnAllowedAlgorithm_SignsAndVerifies(string algorithm)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var key = KeyFor(algorithm);
        var pair = BuildPair(key, [algorithm]);

        var compact = await SignAsync(pair, cancellationToken);
        var verified = await pair.GetRequiredService<ISecurityEventTokenVerifier>()
            .VerifyAsync(compact, cancellationToken: cancellationToken);

        Assert.True(verified.TryGetSuccess(out _), "A token signed with an allowed algorithm did not verify.");
    }

    /// <summary>
    /// A key naming an algorithm the deployment does not allow is refused before anything is signed.
    /// </summary>
    /// <remarks>
    /// The host configured a policy and a key that disagree, and the honest moment to say so is here
    /// rather than at a receiver, which can only report that the signature is not one it accepts.
    /// </remarks>
    [Fact]
    public async Task AKeyOutsideTheAllowlist_IsRefusedBeforeSigning()
    {
        var pair = BuildPair(KeyFor(SigningAlgorithms.PS256), [SigningAlgorithms.RS256]);

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => SignAsync(pair, TestContext.Current.CancellationToken));

        Assert.Contains(SigningAlgorithms.PS256, refusal.Message, StringComparison.Ordinal);
        Assert.Contains(SigningAlgorithms.RS256, refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A key naming NO algorithm is refused too, which is where signing with <c>none</c> would have come
    /// from.
    /// </summary>
    /// <remarks>
    /// The core resolves the algorithm as the key's, then the header's, then <c>none</c> - so a key that
    /// declares nothing, with a header that declares nothing, produces a token whose <c>alg</c> is
    /// <c>none</c> while a signing key is sitting right there. That is the one shape that turns a
    /// transmitter into a source of events stating nothing about who issued them.
    /// </remarks>
    [Fact]
    public async Task AKeyNamingNoAlgorithm_IsRefused()
    {
        var pair = BuildPair(
            JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature), [SigningAlgorithms.RS256]);

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => SignAsync(pair, TestContext.Current.CancellationToken));

        Assert.Contains("no algorithm", refusal.Message, StringComparison.Ordinal);
    }

    /// <summary>
    /// A receiver refuses a signature under an algorithm it does not allow, even when the key verifies it.
    /// </summary>
    /// <remarks>
    /// The transmitter here is willing where the receiver is not, which is the only way to test the
    /// receiving half on its own: the same key, the same signature, and the answer turns on the accepted
    /// set alone.
    /// </remarks>
    [Fact]
    public async Task ASignatureOutsideTheReceiversAllowlist_IsRefused()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var key = KeyFor(SigningAlgorithms.PS256);

        var transmitter = BuildPair(key, [SigningAlgorithms.PS256]);
        var compact = await SignAsync(transmitter, cancellationToken);

        var receiver = BuildPair(key, [SigningAlgorithms.RS256]);
        var verified = await receiver.GetRequiredService<ISecurityEventTokenVerifier>()
            .VerifyAsync(compact, cancellationToken: cancellationToken);

        Assert.False(verified.TryGetSuccess(out _), "A signature outside the accepted set was verified.");
    }

    /// <summary>
    /// A set that allows <c>none</c>, or nothing at all, is refused where the host writes it.
    /// </summary>
    /// <remarks>
    /// At the assignment rather than at startup, because that is the earliest moment the mistake exists
    /// and the only one that can point at the line that made it. An unsigned security event is not a
    /// weaker signature but the absence of one, so this is an invariant of the option rather than a
    /// policy the option carries.
    /// </remarks>
    [Theory]
    [InlineData(SigningAlgorithms.None)]
    [InlineData(SigningAlgorithms.RS256, SigningAlgorithms.None)]
    public void AnAllowlistNamingNone_IsRefused(params string[] algorithms)
        => Assert.Throws<ArgumentException>(
            () => new SecurityEventsOptions
            {
                AllowedSigningAlgorithms = new HashSet<string>(algorithms, StringComparer.Ordinal),
            });

    [Fact]
    public void AnEmptyAllowlist_IsRefused()
        => Assert.Throws<ArgumentException>(
            () => new SecurityEventsOptions
            {
                AllowedSigningAlgorithms = new HashSet<string>(StringComparer.Ordinal),
            });

    private static JsonWebKey KeyFor(string algorithm) => algorithm switch
    {
        SigningAlgorithms.ES256 => JsonWebKeyFactory.CreateEllipticCurve(
            EllipticCurveTypes.P256, SigningAlgorithms.ES256),
        _ => JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, algorithm),
    };

    private static ServiceProvider BuildPair(JsonWebKey key, string[] allowed)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IIssuerKeyResolver>(new FixedKeyResolver(key));
        services.AddSecurityEvents(options =>
        {
            options.SigningKeySource = _ => Task.FromResult(key);
            options.AllowedSigningAlgorithms = new HashSet<string>(allowed, StringComparer.Ordinal);
            options.Events.Register<SomethingHappened>(SomeEvent);
        });

        return services.BuildServiceProvider();
    }

    private static Task<string> SignAsync(IServiceProvider transmitter, CancellationToken cancellationToken)
        => new SecurityEventTokenBuilder()
            .WithIssuer(Issuer)
            .WithAudience(Audience)
            .WithJwtId("evt-1")
            .WithIssuedAt(DateTimeOffset.FromUnixTimeSeconds(1754040000))
            .WithEvent(SomeEvent, new SomethingHappened())
            .SignAsync(transmitter.GetRequiredService<ISecurityEventTokenSigner>(), cancellationToken);
}
