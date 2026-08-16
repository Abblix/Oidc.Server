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

using System.Net;
using System.Net.Http.Json;
using Abblix.Jwt;
using Abblix.SecurityEvents.Infrastructure;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Pins the resolver's caching contract: the hot path fetches nothing, expiry and an unseen "kid"
/// are the two refetch triggers, the cooldown keeps a bogus identifier from turning the second
/// trigger into a hammer, and only signature-usable keys answer.
/// </summary>
public class JwksIssuerKeyResolverTests
{
    private const string Issuer = "https://issuer.example.com";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    /// <summary>
    /// Serves a JWK Set from memory, recording every request: the counter is the assertion the
    /// caching contract is judged by.
    /// </summary>
    private sealed class CountingJwksHandler(Func<JsonWebKeySet> keySet) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(keySet()),
            });
        }
    }

    private sealed class SingleClientFactory(HttpMessageHandler handler) : IHttpClientFactory
    {
        public HttpClient CreateClient(string name) => new(handler, disposeHandler: false);
    }

    private static JwksIssuerKeyResolver Resolver(
        HttpMessageHandler handler,
        TimeProvider clock,
        JwksKeyResolutionOptions? options = null)
        => new(new SingleClientFactory(handler), clock, Options.Create(options ?? new JwksKeyResolutionOptions()));

    private static async Task<List<JsonWebKey>> Resolve(
        JwksIssuerKeyResolver resolver,
        string? keyId = null)
    {
        var keys = new List<JsonWebKey>();
        await foreach (var key in resolver.ResolveSigningKeysAsync(
                           Issuer, keyId, TestContext.Current.CancellationToken))
        {
            keys.Add(key);
        }

        return keys;
    }

    [Fact]
    public async Task FirstResolution_FetchesTheWellKnownDocument()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));

        var keys = await Resolve(Resolver(handler, new FakeTimeProvider(Now)));

        var request = Assert.Single(handler.Requests);
        Assert.Equal(new Uri("https://issuer.example.com/.well-known/jwks.json"), request);
        Assert.Equal(key.KeyId, Assert.Single(keys).KeyId);
    }

    [Fact]
    public async Task SecondResolution_WithinTheLifetime_AnswersFromCache()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));
        var resolver = Resolver(handler, new FakeTimeProvider(Now));

        await Resolve(resolver);
        await Resolve(resolver, key.KeyId);

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task ExpiredCache_Refetches()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));
        var clock = new FakeTimeProvider(Now);
        var resolver = Resolver(handler, clock, new JwksKeyResolutionOptions
        {
            CacheLifetime = TimeSpan.FromMinutes(15),
        });

        await Resolve(resolver);
        clock.Advance(TimeSpan.FromMinutes(16));
        await Resolve(resolver);

        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task UnseenKeyIdentifier_ForcesOneRefetch_AndTheCooldownStopsTheNext()
    {
        // The rollover story: the issuer rotated, a token arrives under the new "kid", and the
        // resolver notices before the cache expires - exactly once per cooldown window, so a
        // flood of bogus identifiers cannot drive traffic to the issuer.
        var oldKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var newKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var served = new JsonWebKeySet([oldKey]);
        var handler = new CountingJwksHandler(() => served);
        var clock = new FakeTimeProvider(Now);
        var resolver = Resolver(handler, clock, new JwksKeyResolutionOptions
        {
            CacheLifetime = TimeSpan.FromMinutes(15),
            RolloverRefetchCooldown = TimeSpan.FromSeconds(30),
        });

        await Resolve(resolver);
        Assert.Single(handler.Requests);

        // The issuer rotates; the receiver's next token names the new key after the cooldown.
        served = new JsonWebKeySet([oldKey, newKey]);
        clock.Advance(TimeSpan.FromSeconds(31));

        var keys = await Resolve(resolver, newKey.KeyId);
        Assert.Equal(2, handler.Requests.Count);
        Assert.Contains(keys, key => key.KeyId == newKey.KeyId);

        // A bogus identifier right after the refetch stays inside the cooldown: cache answers.
        await Resolve(resolver, "kid-that-exists-nowhere");
        Assert.Equal(2, handler.Requests.Count);
    }

    [Fact]
    public async Task KnownKeyIdentifier_NeverRefetches()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));
        var clock = new FakeTimeProvider(Now);
        var resolver = Resolver(handler, clock);

        await Resolve(resolver);
        clock.Advance(TimeSpan.FromMinutes(5));
        await Resolve(resolver, key.KeyId);

        Assert.Single(handler.Requests);
    }

    [Fact]
    public async Task UriSelector_Overrides_TheWellKnownConvention()
    {
        // A Shared Signals transmitter advertises its jwks_uri in ssf-configuration; that value,
        // not the convention, is authoritative for it.
        var advertised = new Uri("https://issuer.example.com/ssf/jwks");
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));

        await Resolve(Resolver(handler, new FakeTimeProvider(Now), new JwksKeyResolutionOptions
        {
            JwksUriSelector = _ => advertised,
        }));

        Assert.Equal(advertised, Assert.Single(handler.Requests));
    }

    /// <summary>A named entry answers for its issuer, ahead of the convention.</summary>
    [Fact]
    public async Task ANamedEntry_Overrides_TheWellKnownConvention()
    {
        var mapped = new Uri("https://issuer.example.com/.well-known/jwks");
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));

        var options = new JwksKeyResolutionOptions();
        options.JwksUris[Issuer] = mapped;

        await Resolve(Resolver(handler, new FakeTimeProvider(Now), options));

        Assert.Equal(mapped, Assert.Single(handler.Requests));
    }

    /// <summary>
    ///     Two consumers naming two issuers do not take each other's keys away.
    /// </summary>
    /// <remarks>
    ///     The failure this replaces: with one selector for the whole host, every consumer past the
    ///     first composed a chain by hand, and one that forgot to call the previous delegate removed
    ///     another issuer's keys silently - a token that used to verify starts failing its
    ///     signature, which reads as an attack rather than as wiring.
    /// </remarks>
    [Fact]
    public async Task TwoNamedIssuers_DoNotDisplaceEachOther()
    {
        var ours = new Uri("https://issuer.example.com/keys");
        var theirs = new Uri("https://transmitter.example.com/ssf/jwks");
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));

        var options = new JwksKeyResolutionOptions();
        options.JwksUris[Issuer] = ours;
        options.JwksUris["https://transmitter.example.com"] = theirs;

        var resolver = Resolver(handler, new FakeTimeProvider(Now), options);
        await Resolve(resolver);
        await foreach (var _ in resolver.ResolveSigningKeysAsync(
                           "https://transmitter.example.com", null, TestContext.Current.CancellationToken))
        {
            // Draining the sequence is what performs the fetch; the keys themselves are not the point.
        }

        Assert.Equal([ours, theirs], handler.Requests);
    }

    /// <summary>
    ///     A selector that does not recognise an issuer falls through rather than deciding.
    /// </summary>
    /// <remarks>
    ///     Returning null is what keeps the sources composable. A delegate that threw for an issuer
    ///     it did not know would also take out the well-known fallback for every other issuer, since
    ///     nothing runs after it - and the host would look configured while resolving nothing.
    /// </remarks>
    [Fact]
    public async Task ASelectorAnsweringNull_FallsThroughToTheConvention()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));

        await Resolve(Resolver(handler, new FakeTimeProvider(Now), new JwksKeyResolutionOptions
        {
            JwksUriSelector = _ => null,
        }));

        Assert.Equal(new Uri($"{Issuer}/.well-known/jwks.json"), Assert.Single(handler.Requests));
    }

    /// <summary>A named entry is consulted before the selector: the more specific statement wins.</summary>
    [Fact]
    public async Task ANamedEntry_IsConsultedBeforeTheSelector()
    {
        var mapped = new Uri("https://issuer.example.com/keys");
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));

        var options = new JwksKeyResolutionOptions
        {
            JwksUriSelector = _ => new Uri("https://issuer.example.com/from-selector"),
        };
        options.JwksUris[Issuer] = mapped;

        await Resolve(Resolver(handler, new FakeTimeProvider(Now), options));

        Assert.Equal(mapped, Assert.Single(handler.Requests));
    }

    [Fact]
    public async Task EncryptionKeys_DoNotAnswerASigningQuestion()
    {
        var signingKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var encryptionKey = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Encryption);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([signingKey, encryptionKey]));

        var keys = await Resolve(Resolver(handler, new FakeTimeProvider(Now)));

        Assert.Equal(signingKey.KeyId, Assert.Single(keys).KeyId);
    }

    [Fact]
    public async Task CleartextHttpIssuer_IsRefusedBeforeAnyRequestLeaves()
    {
        // The fetched document decides which signatures verify, so over cleartext HTTP a
        // path-sitting attacker substitutes a key and forges tokens at will. The refusal must
        // come before the request: a fetch that leaks and then fails has already spoken.
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([]));
        var resolver = Resolver(handler, new FakeTimeProvider(Now));

        var error = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
        {
            await foreach (var key in resolver.ResolveSigningKeysAsync(
                               "http://issuer.example.com",
                               cancellationToken: TestContext.Current.CancellationToken))
            {
                Assert.Fail($"No key should resolve over cleartext HTTP, yet '{key.KeyId}' did.");
            }
        });

        Assert.Contains("cleartext", error.Message);
        Assert.Empty(handler.Requests);
    }

    [Fact]
    public async Task LoopbackHttpIssuer_StaysAvailableForLocalDevelopment()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));
        var resolver = Resolver(handler, new FakeTimeProvider(Now));

        var keys = new List<JsonWebKey>();
        await foreach (var resolved in resolver.ResolveSigningKeysAsync(
                           "http://localhost:5000",
                           cancellationToken: TestContext.Current.CancellationToken))
        {
            keys.Add(resolved);
        }

        Assert.Equal(new Uri("http://localhost:5000/.well-known/jwks.json"), Assert.Single(handler.Requests));
        Assert.Equal(key.KeyId, Assert.Single(keys).KeyId);
    }
}
