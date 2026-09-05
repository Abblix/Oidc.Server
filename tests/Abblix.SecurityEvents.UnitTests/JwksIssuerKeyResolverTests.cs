// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using System.Net.Http.Json;
using System.Text.Json.Nodes;
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

    /// <summary>
    /// Serves a discovery document and a key set from two different addresses, recording the order
    /// they were asked for: the order is the assertion, because reading the document is what makes
    /// the key location the issuer's statement rather than this resolver's guess.
    /// </summary>
    private sealed class DiscoveringHandler(
        Uri discoveryUri,
        Uri jwksUri,
        JsonWebKeySet keySet,
        string? declaredIssuer = null) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            var uri = request.RequestUri!;
            Requests.Add(uri);

            if (uri == discoveryUri)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(new JsonObject
                    {
                        ["issuer"] = declaredIssuer ?? Issuer,
                        ["jwks_uri"] = jwksUri.AbsoluteUri,
                    }),
                });
            }

            if (uri == jwksUri)
            {
                return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
                {
                    Content = JsonContent.Create(keySet),
                });
            }

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.NotFound));
        }
    }

    /// <summary>Serves one JSON document to every address, recording what was asked for.</summary>
    private sealed class StaticJsonHandler(JsonObject document) : HttpMessageHandler
    {
        public List<Uri> Requests { get; } = [];

        protected override Task<HttpResponseMessage> SendAsync(
            HttpRequestMessage request,
            CancellationToken cancellationToken)
        {
            Requests.Add(request.RequestUri!);

            return Task.FromResult(new HttpResponseMessage(HttpStatusCode.OK)
            {
                Content = JsonContent.Create(document),
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
        string? keyId = null,
        string? issuer = null)
    {
        var keys = new List<JsonWebKey>();
        await foreach (var key in resolver.ResolveSigningKeysAsync(
                           issuer ?? Issuer, keyId, TestContext.Current.CancellationToken))
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

    /// <summary>
    /// With the discovery document in use, the keys come from the "jwks_uri" the issuer publishes,
    /// at whatever address that names - and the document is read first. A guessed location is a
    /// snapshot of where the keys were: move them at the provider and every token starts failing
    /// signature verification here, while the same application's sign-in keeps working because it
    /// re-reads discovery.
    /// </summary>
    [Fact]
    public async Task WithDiscoveryEnabled_TheKeysComeFromTheAddressTheIssuerPublishes()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var discoveryUri = new Uri($"{Issuer}/.well-known/openid-configuration");
        var jwksUri = new Uri("https://keys.example.net/tenants/7/signing-keys");
        var handler = new DiscoveringHandler(discoveryUri, jwksUri, new JsonWebKeySet([key]));

        var keys = await Resolve(Resolver(
            handler,
            new FakeTimeProvider(Now),
            new JwksKeyResolutionOptions { UseDiscoveryDocument = true }));

        Assert.Equal([discoveryUri, jwksUri], handler.Requests);
        Assert.Equal(key.KeyId, Assert.Single(keys).KeyId);
    }

    /// <summary>
    /// A discovery document that names no usable "jwks_uri" fails loudly instead of quietly guessing
    /// the convention. A host turns discovery on to stop guessing; guessing again behind its back
    /// would restore the snapshot it was removing, and the damage would surface much later as
    /// signatures that stop verifying.
    /// </summary>
    [Fact]
    public async Task ADiscoveryDocumentWithoutAKeyAddress_FailsNamingTheOption()
    {
        var discoveryUri = new Uri($"{Issuer}/.well-known/openid-configuration");
        var handler = new StaticJsonHandler(new JsonObject { ["issuer"] = Issuer });

        var resolver = Resolver(
            handler,
            new FakeTimeProvider(Now),
            new JwksKeyResolutionOptions { UseDiscoveryDocument = true });

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Resolve(resolver));

        Assert.Contains(discoveryUri.AbsoluteUri, error.Message, StringComparison.Ordinal);
        Assert.Contains(nameof(JwksKeyResolutionOptions.UseDiscoveryDocument), error.Message, StringComparison.Ordinal);

        // Positive form on purpose: "no request whose path ends in jwks.json" also passes when
        // nothing was requested at all, and when the convention is respelled. Exactly one
        // request, to the document, says what happened in both directions.
        Assert.Equal(discoveryUri, Assert.Single(handler.Requests));
    }

    /// <summary>
    /// A named entry still wins over discovery, so a host that knows better about one issuer keeps
    /// saying so. Discovery replaces the guess that used to follow the map and the selectors, not
    /// the host's own statement.
    /// </summary>
    [Fact]
    public async Task ANamedEntry_Wins_OverDiscovery()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var named = new Uri("https://keys.example.org/named");
        var handler = new DiscoveringHandler(
            new Uri($"{Issuer}/.well-known/openid-configuration"),
            named,
            new JsonWebKeySet([key]));

        var options = new JwksKeyResolutionOptions { UseDiscoveryDocument = true };
        options.JwksUris[Issuer] = named;

        var keys = await Resolve(Resolver(handler, new FakeTimeProvider(Now), options));

        Assert.Equal(named, Assert.Single(handler.Requests));
        Assert.Equal(key.KeyId, Assert.Single(keys).KeyId);
    }

    /// <summary>
    /// RFC 8414 Section 3.3: a document asserting a different issuer than the one it was fetched
    /// for MUST NOT be used. Without the check, a document served on one issuer path - or reached
    /// by a redirect - answers for another issuer of the same host, and every token afterwards
    /// verifies against the wrong key set, silently and permanently.
    /// </summary>
    [Fact]
    public async Task ADocumentAssertingAnotherIssuer_IsRefused()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var discoveryUri = new Uri($"{Issuer}/.well-known/openid-configuration");
        var handler = new DiscoveringHandler(
            discoveryUri,
            new Uri("https://keys.example.net/keys"),
            new JsonWebKeySet([key]),
            declaredIssuer: "https://other.example.com");

        var resolver = Resolver(
            handler,
            new FakeTimeProvider(Now),
            new JwksKeyResolutionOptions { UseDiscoveryDocument = true });

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Resolve(resolver));

        Assert.Contains("https://other.example.com", error.Message, StringComparison.Ordinal);
        Assert.Contains(Issuer, error.Message, StringComparison.Ordinal);

        // Refused before the key set was fetched: the document decides which keys are trusted, so
        // a rejected document must not still have chosen them.
        Assert.Equal(discoveryUri, Assert.Single(handler.Requests));
    }

    /// <summary>
    /// A key address the document chose does not inherit the loopback exemption, which exists for
    /// an address this host chose. Otherwise an issuer reached over HTTPS aims the receiver at its
    /// own loopback, over cleartext, on every cache miss - and the receiver makes that request
    /// blind, on behalf of whoever wrote the document.
    /// </summary>
    [Fact]
    public async Task ADiscoveredLoopbackAddress_IsRefused_WhenTheIssuerIsNot()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var discoveryUri = new Uri($"{Issuer}/.well-known/openid-configuration");
        var handler = new DiscoveringHandler(
            discoveryUri,
            new Uri("http://127.0.0.1:8200/v1/secret/keys"),
            new JsonWebKeySet([key]));

        var resolver = Resolver(
            handler,
            new FakeTimeProvider(Now),
            new JwksKeyResolutionOptions { UseDiscoveryDocument = true });

        var error = await Assert.ThrowsAsync<InvalidOperationException>(() => Resolve(resolver));

        Assert.Contains("cleartext", error.Message, StringComparison.Ordinal);
        Assert.Equal(discoveryUri, Assert.Single(handler.Requests));
    }

    /// <summary>
    /// The transport rule covers the discovery document itself, and refuses before any request
    /// leaves: that document names the key set, so substituting it substitutes the keys.
    /// </summary>
    [Fact]
    public async Task ACleartextIssuer_IsRefused_BeforeTheDocumentIsFetched()
    {
        var handler = new StaticJsonHandler(new JsonObject { ["issuer"] = "http://issuer.example.com" });

        var resolver = Resolver(
            handler,
            new FakeTimeProvider(Now),
            new JwksKeyResolutionOptions { UseDiscoveryDocument = true });

        var error = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Resolve(resolver, issuer: "http://issuer.example.com"));

        Assert.Contains("cleartext", error.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Requests);
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

        await Resolve(Resolver(
            handler,
            new FakeTimeProvider(Now),
            new JwksKeyResolutionOptions().AddJwksUriSelector(_ => advertised)));

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
    ///     A selector answering null reaches the convention, which is what makes null the right
    ///     way to say "not mine".
    /// </summary>
    /// <remarks>
    ///     The resolver treats a null RESULT the same as a null delegate, and the annotation permits
    ///     the answer - so a selector may decline an issuer it does not know rather than throw for
    ///     it. A throw would take the fallback out for every other issuer, since nothing runs past
    ///     it, which is what makes the permitted answer worth pinning.
    /// </remarks>
    [Fact]
    public async Task ASelectorAnsweringNull_FallsThroughToTheConvention()
    {
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));

        await Resolve(Resolver(
            handler,
            new FakeTimeProvider(Now),
            new JwksKeyResolutionOptions().AddJwksUriSelector(_ => null)));

        Assert.Equal(new Uri($"{Issuer}/.well-known/jwks.json"), Assert.Single(handler.Requests));
    }

    /// <summary>
    ///     A trailing slash on either side does not decide which document the keys come from.
    /// </summary>
    /// <remarks>
    ///     One method decides twice - it looks an issuer up in the map and, failing that, composes
    ///     the well-known address - so the two halves must agree about what an issuer IS. Matching
    ///     the raw string on one side while trimming on the other makes a map keyed with the slash
    ///     miss a token whose "iss" carries none, and the miss does not fail: it falls through to
    ///     the convention, which may well serve a document that verifies nothing this issuer signed.
    /// </remarks>
    [Theory]
    [InlineData("https://issuer.example.com/", "https://issuer.example.com")]
    [InlineData("https://issuer.example.com", "https://issuer.example.com/")]
    public async Task ATrailingSlash_DoesNotDecideWhichDocumentIsRead(string mapKey, string tokenIssuer)
    {
        var mapped = new Uri("https://issuer.example.com/keys");
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));

        var options = new JwksKeyResolutionOptions();
        options.JwksUris[mapKey] = mapped;

        var resolver = Resolver(handler, new FakeTimeProvider(Now), options);
        await foreach (var _ in resolver.ResolveSigningKeysAsync(
                           tokenIssuer, null, TestContext.Current.CancellationToken))
        {
            // Draining the sequence is what performs the fetch; the keys themselves are not the point.
        }

        Assert.Equal(mapped, Assert.Single(handler.Requests));
    }

    /// <summary>
    ///     Two selectors both answer, in the order they were added, and neither displaces the other.
    /// </summary>
    /// <remarks>
    ///     Two receivers each learning their own transmitter's metadata is the ordinary case, not an
    ///     exotic one. A settable delegate would let the second discard the first, and the loss
    ///     shows up as a signature that stopped verifying - which reads as an attack rather than as
    ///     wiring.
    /// </remarks>
    [Fact]
    public async Task TwoSelectors_BothAnswer_InTheOrderTheyWereAdded()
    {
        var ours = new Uri("https://issuer.example.com/keys");
        var theirs = new Uri("https://transmitter.example.com/ssf/jwks");
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));

        var options = new JwksKeyResolutionOptions()
            .AddJwksUriSelector(issuer => issuer == Issuer ? ours : null)
            .AddJwksUriSelector(issuer => issuer == "https://transmitter.example.com" ? theirs : null);

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
    ///     A mapped address over cleartext is refused, exactly as a derived one is.
    /// </summary>
    /// <remarks>
    ///     The document behind this address decides which signatures verify, so its transport is
    ///     part of the trust whatever named it. A map that quietly escaped the check would be a way
    ///     to lower it by writing one line of wiring - and the check is the reason nobody can.
    /// </remarks>
    [Fact]
    public async Task AMappedCleartextAddress_IsRefused()
    {
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([]));
        var options = new JwksKeyResolutionOptions();
        options.JwksUris[Issuer] = new Uri("http://issuer.example.com/keys");

        var failure = await Assert.ThrowsAsync<InvalidOperationException>(
            () => Resolve(Resolver(handler, new FakeTimeProvider(Now), options)));

        Assert.Contains("cleartext", failure.Message, StringComparison.Ordinal);
        Assert.Empty(handler.Requests);
    }

    /// <summary>Loopback stays reachable over cleartext, so local development is not collateral.</summary>
    /// <remarks>
    ///     The control for the case above: without it, the refusal test would also pass against a
    ///     resolver that refused every mapped address, and the map would be unusable while the suite
    ///     read as green.
    /// </remarks>
    [Fact]
    public async Task AMappedLoopbackAddress_IsAllowed()
    {
        var mapped = new Uri("http://localhost:5001/keys");
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));

        var options = new JwksKeyResolutionOptions();
        options.JwksUris[Issuer] = mapped;

        await Resolve(Resolver(handler, new FakeTimeProvider(Now), options));

        Assert.Equal(mapped, Assert.Single(handler.Requests));
    }

    /// <summary>A named entry is consulted before the selector: the more specific statement wins.</summary>
    [Fact]
    public async Task ANamedEntry_IsConsultedBeforeTheSelector()
    {
        var mapped = new Uri("https://issuer.example.com/keys");
        var key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);
        var handler = new CountingJwksHandler(() => new JsonWebKeySet([key]));

        var options = new JwksKeyResolutionOptions()
            .AddJwksUriSelector(_ => new Uri("https://issuer.example.com/from-selector"));
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
