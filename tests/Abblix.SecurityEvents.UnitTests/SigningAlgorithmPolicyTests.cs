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
using Abblix.SecurityEvents.Validation;
using Microsoft.Extensions.Configuration;
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
                AllowedSigningAlgorithms = algorithms,
            });

    [Fact]
    public void AnEmptyAllowlist_IsRefused()
        => Assert.Throws<ArgumentException>(
            () => new SecurityEventsOptions
            {
                AllowedSigningAlgorithms = [],
            });


    /// <summary>
    /// The default is RS256 alone, and a host that needs another algorithm widens it.
    /// </summary>
    /// <remarks>
    /// Two specifications arrive at RS256 independently - the CAEP Interoperability Profile requires it
    /// of security events, and Back-Channel Logout 1.0 names it as the default for a Logout Token - and
    /// this server's own logout tokens carry it unless a client registered otherwise. So the two ends of
    /// a deployment using our own pieces agree with nobody configuring anything, which is what makes the
    /// narrow default the safe one rather than the awkward one.
    /// <para>
    /// The widening half is the row's other case, and it is not decoration: the verifier is SHARED, so a
    /// host receiving Back-Channel Logout from a provider whose clients registered ES256 resolves this
    /// same one and must name it here. Without that case a default that refused everything would pass.
    /// </para>
    /// </remarks>
    [Theory]
    [InlineData(SigningAlgorithms.RS256, true)]
    [InlineData(SigningAlgorithms.PS256, false)]
    [InlineData(SigningAlgorithms.ES256, false)]
    public async Task TheDefaultSet_IsRS256Alone(string algorithm, bool acceptedByDefault)
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var key = KeyFor(algorithm);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<IIssuerKeyResolver>(new FixedKeyResolver(key));
        services.AddSecurityEvents(options =>
        {
            options.SigningKeySource = _ => Task.FromResult(key);
            options.Events.Register<SomethingHappened>(SomeEvent);
        });

        await using var host = services.BuildServiceProvider();

        // Signed by a transmitter that allows this algorithm, so what the row measures is the RECEIVING
        // half alone: the signer's own policy would otherwise refuse before anything reached a verifier.
        var compact = await SignAsync(BuildPair(key, [algorithm]), cancellationToken);

        var verified = await host.GetRequiredService<ISecurityEventTokenVerifier>()
            .VerifyAsync(compact, cancellationToken: cancellationToken);

        Assert.Equal(acceptedByDefault, verified.TryGetSuccess(out _));

        // And widening admits it, which is the move the documentation tells such a host to make.
        var widened = BuildPair(key, [algorithm]);
        var accepted = await widened.GetRequiredService<ISecurityEventTokenVerifier>()
            .VerifyAsync(compact, cancellationToken: cancellationToken);

        Assert.True(accepted.TryGetSuccess(out _), $"{algorithm} was refused after widening.");
    }

    /// <summary>
    /// The refusal names the algorithm and the way out, rather than reading as a bad signature.
    /// </summary>
    /// <remarks>
    /// A narrow default is only workable if the host that meets it can tell what happened. An algorithm
    /// outside the set is a POLICY decision; answering it the way a tampered token is answered sends an
    /// operator looking for an attacker while the fix is one line of configuration - which is the same
    /// defect as a key-size refusal arriving as <c>invalid_signature</c>.
    /// </remarks>
    [Fact]
    public async Task AnAlgorithmOutsideTheSet_IsRefusedAsAPolicyDecision()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var key = KeyFor(SigningAlgorithms.ES256);

        var compact = await SignAsync(BuildPair(key, [SigningAlgorithms.ES256]), cancellationToken);
        var receiver = BuildPair(key, [SigningAlgorithms.RS256]);

        var verified = await receiver.GetRequiredService<ISecurityEventTokenVerifier>()
            .VerifyAsync(compact, cancellationToken: cancellationToken);

        Assert.True(verified.TryGetFailure(out var error));
        Assert.NotEqual(SecurityEventTokenErrorCode.SignatureInvalid, error.Code);
        Assert.Contains(SigningAlgorithms.ES256, error.Description, StringComparison.Ordinal);
        Assert.Contains(
            nameof(SecurityEventsOptions.AllowedSigningAlgorithms),
            error.Description,
            StringComparison.Ordinal);
    }

    /// <summary>
    /// The set is copied on assignment, so a caller cannot add <c>none</c> to it afterwards.
    /// </summary>
    /// <remarks>
    /// An invariant a caller can break after assignment is not one, and the refusal in the setter is the
    /// only thing keeping an unsigned event out.
    /// </remarks>
    [Fact]
    public void TheAllowlist_IsCopiedFromTheCaller()
    {
        // The caller's own array goes IN, which the first version of this row forgot to do - it built
        // one and assigned a different literal, so deleting the copy left every test green.
        var caller = new[] { SigningAlgorithms.RS256 };
        var options = new SecurityEventsOptions { AllowedSigningAlgorithms = caller };

        caller[0] = SigningAlgorithms.None;

        Assert.DoesNotContain(SigningAlgorithms.None, options.EffectiveSigningAlgorithms);

        // And the way out, which the inbound copy alone leaves open: what the getter hands back is a copy
        // too, so writing into it does not reach the signer.
        options.AllowedSigningAlgorithms![0] = SigningAlgorithms.None;

        Assert.DoesNotContain(SigningAlgorithms.None, options.EffectiveSigningAlgorithms);
    }

    /// <summary>
    /// A host binding the set from configuration REPLACES it rather than adding to it.
    /// </summary>
    /// <remarks>
    /// What carries this is that the default lives OUTSIDE the property, not that the property is an
    /// array: the binder reads whatever is there, adds the configured values and writes the result back,
    /// and it unions an array exactly as it unions a set - measured on both. With nothing there, what it
    /// writes back is exactly what was configured, which is what "narrow" has to mean.
    /// </remarks>
    [Fact]
    public void TheAllowlist_BoundFromConfiguration_ReplacesTheDefault()
    {
        var configuration = new ConfigurationBuilder()
            .AddInMemoryCollection(new Dictionary<string, string?>
            {
                ["AllowedSigningAlgorithms:0"] = SigningAlgorithms.ES256,
            })
            .Build();

        var options = new SecurityEventsOptions();
        configuration.Bind(options);

        Assert.Equal([SigningAlgorithms.ES256], options.AllowedSigningAlgorithms!);
        Assert.Equal([SigningAlgorithms.ES256], options.EffectiveSigningAlgorithms);
    }

    /// <summary>
    /// The core's own refusals are still reachable: a header and a key naming different algorithms is a
    /// mismatch, not something this signer quietly resolves.
    /// </summary>
    /// <remarks>
    /// The first version of this change wrote the resolved algorithm into the header, which agreed with
    /// the core at the cost of making two of its refusals unreachable - and it changed no algorithm,
    /// since the value written was the one the core would have computed. Nothing measured it either way.
    /// </remarks>
    [Fact]
    public async Task AHeaderAndAKeyNamingDifferentAlgorithms_IsStillRefusedByTheCore()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var key = KeyFor(SigningAlgorithms.RS256);
        var pair = BuildPair(key, [SigningAlgorithms.RS256]);

        var token = new SecurityEventTokenBuilder()
            .WithIssuer(Issuer)
            .WithAudience(Audience)
            .WithJwtId("evt-1")
            .WithIssuedAt(DateTimeOffset.FromUnixTimeSeconds(1754040000))
            .WithEvent(SomeEvent, new SomethingHappened())
            .Build();

        token.Token.Header.Algorithm = SigningAlgorithms.PS256;

        var refusal = await Assert.ThrowsAsync<InvalidOperationException>(
            () => pair.GetRequiredService<ISecurityEventTokenSigner>().SignAsync(token, cancellationToken));

        Assert.Contains("mismatch", refusal.Message, StringComparison.OrdinalIgnoreCase);
    }

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
            options.AllowedSigningAlgorithms = allowed;
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
