// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Runtime.CompilerServices;
using System.Text.Json;
using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;
using Microsoft.Extensions.Options;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// Resolves issuers' verification keys from their published JWK Set documents, cached so the hot
/// path of validation performs no network I/O.
/// </summary>
/// <remarks>
/// <para>
/// A key rollover is noticed two ways: the cache lifetime expires, or a token names a "kid" the
/// cached set lacks - the earliest possible signal - which forces one refetch, rate-limited so a
/// flood of bogus identifiers cannot turn it into hammering the issuer. Concurrent resolutions
/// may fetch the same document twice; the copies are identical and the last write wins, which is
/// cheaper than a lock on every validation.
/// </para>
/// <para>
/// A fetch failure propagates as its exception rather than as an empty key set: empty means "this
/// issuer is not trusted", a verdict about the token, while an unreachable JWKS endpoint is an
/// infrastructure failure the delivery endpoint should answer with a retryable status, not with
/// "invalid key".
/// </para>
/// </remarks>
/// <param name="httpClientFactory">
/// Supplies the HTTP client, created per fetch under <see cref="JwksTransport.HttpClientName"/> so a host can
/// configure the named client - timeouts, proxy, resilience - without touching this type.</param>
/// <param name="clock">Drives cache expiry and the rollover cooldown.</param>
/// <param name="options">Where key sets live and how long they answer from cache.</param>
public sealed class JwksIssuerKeyResolver(
    IHttpClientFactory httpClientFactory,
    TimeProvider clock,
    IOptions<JwksKeyResolutionOptions> options) : IIssuerKeyResolver
{
    private sealed record CachedKeySet(IReadOnlyList<JsonWebKey> Keys, DateTimeOffset FetchedAt);

    private readonly ConcurrentDictionary<string, CachedKeySet> _cache = new(StringComparer.Ordinal);

    /// <inheritdoc />
    public async IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
        string issuer,
        string? keyId = null,
        [EnumeratorCancellation] CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrEmpty(issuer);

        var now = clock.GetUtcNow();
        var entry = _cache.TryGetValue(issuer, out var cached) ? cached : null;

        if (ShouldFetch(entry, keyId, now))
        {
            entry = new CachedKeySet(await FetchKeysAsync(issuer, cancellationToken), now);
            _cache[issuer] = entry;
        }

        foreach (var key in entry!.Keys)
        {
            yield return key;
        }
    }

    private bool ShouldFetch(CachedKeySet? entry, string? keyId, DateTimeOffset now)
    {
        if (entry is null || now - entry.FetchedAt >= options.Value.CacheLifetime)
        {
            return true;
        }

        // The rollover signal: the token names a key the cache has never seen. One refetch may
        // heal it; repeating the refetch for every such token would let anyone with a bogus
        // "kid" drive traffic to the issuer, hence the cooldown.
        return keyId is not null
            && now - entry.FetchedAt >= options.Value.RolloverRefetchCooldown
            && entry.Keys.All(key => key.KeyId != keyId);
    }

    private async Task<IReadOnlyList<JsonWebKey>> FetchKeysAsync(string issuer, CancellationToken cancellationToken)
    {
        var jwksUri = options.Value.ResolveJwksUri(issuer)
            ?? await DiscoverJwksUriAsync(issuer, cancellationToken)
            ?? DeriveWellKnownUri(issuer);

        // Host-chosen when it came from the map, a selector or the convention; a discovered
        // address was already checked against its own origin before it got here.
        RequireSecureTransport(jwksUri, "signature verification keys", allowLoopback: true);

        using var client = httpClientFactory.CreateClient(JwksTransport.HttpClientName);
        var keySet = await client.GetFromJsonAsync<JsonWebKeySet>(jwksUri, cancellationToken)
            ?? throw new InvalidOperationException($"The JWK Set document at '{jwksUri}' deserialized to null.");

        // A JWKS may carry encryption keys beside verification ones; only keys usable for
        // signature verification answer this resolver's question. A key declaring no usage is
        // kept - RFC 7517 Section 4.2 makes "use" OPTIONAL, so absence is not "not for signing".
        return keySet.Keys
            .Where(key => key.Usage is null or PublicKeyUsages.Signature)
            .ToArray();
    }

    /// <summary>
    /// Asks the issuer where its keys are, when the host opted into that. Returns null when it did
    /// not, leaving the caller's fallback in charge.
    /// </summary>
    /// <remarks>
    /// A document that names no "jwks_uri" fails rather than falling back to the convention: a host
    /// that turned this on did so to stop guessing, and quietly guessing again would put back the
    /// snapshot it was trying to remove - visible only later, as signatures that stop verifying.
    /// </remarks>
    private async Task<Uri?> DiscoverJwksUriAsync(string issuer, CancellationToken cancellationToken)
    {
        if (!options.Value.UseDiscoveryDocument)
            return null;

        // Composed through the same normalisation as the map comparer and the well-known
        // convention. A second spelling here would let the three disagree about one issuer, and
        // the disagreement fetches a different document rather than failing.
        var normalised = JwksKeyResolutionOptions.NormaliseIssuer(issuer);
        var origin = new Uri(normalised);

        // Composed from the normalised STRING, not from the Uri: Uri.ToString() of a bare
        // authority carries a trailing slash, which would make this address double-slashed.
        var discoveryUri = new Uri($"{normalised}/.well-known/openid-configuration");
        RequireSecureTransport(discoveryUri, "the discovery document", allowLoopback: true);

        using var client = httpClientFactory.CreateClient(JwksTransport.HttpClientName);
        var document = await ReadDocumentAsync(client, discoveryUri, cancellationToken);

        RequireDeclaredIssuer(document, discoveryUri, origin);

        var declared = document.TryGetProperty("jwks_uri", out var jwksUri)
                       && jwksUri.ValueKind == JsonValueKind.String
            ? jwksUri.GetString()
            : null;

        if (!Uri.TryCreate(declared, UriKind.Absolute, out var resolved))
        {
            throw new InvalidOperationException(
                $"The discovery document at '{discoveryUri}' names no usable \"jwks_uri\", so the keys of "
                + $"'{issuer}' cannot be located. Point this issuer at its key set explicitly, or turn "
                + $"{nameof(JwksKeyResolutionOptions.UseDiscoveryDocument)} off.");
        }

        // This address came out of a document rather than from this host, so the loopback
        // exemption applies only when the issuer being trusted is itself loopback. Without that
        // condition a remote issuer aims the receiver at its own loopback, over cleartext, on
        // every cache miss.
        RequireSecureTransport(resolved, "signature verification keys", allowLoopback: origin.IsLoopback);

        return resolved;
    }

    /// <summary>
    /// Reads the discovery document as a JSON object, so a response that is not one is named
    /// here instead of surfacing as a type complaint from the reader with no address in it.
    /// </summary>
    private static async Task<JsonElement> ReadDocumentAsync(
        HttpClient client,
        Uri discoveryUri,
        CancellationToken cancellationToken)
    {
        var document = await client.GetFromJsonAsync<JsonElement>(discoveryUri, cancellationToken);
        if (document.ValueKind == JsonValueKind.Object)
            return document;

        throw new InvalidOperationException(
            $"The discovery document at '{discoveryUri}' is {document.ValueKind}, not a JSON object. "
            + "Point this issuer at its key set explicitly, or turn "
            + $"{nameof(JwksKeyResolutionOptions.UseDiscoveryDocument)} off.");
    }

    /// <summary>
    /// RFC 8414 Section 3.3: the "issuer" a document returns MUST be identical to the one whose
    /// well-known URI was used to fetch it, and a document failing that MUST NOT be used.
    /// </summary>
    /// <remarks>
    /// Compared as AbsoluteUri rather than with Uri.Equals, which ignores userinfo and fragment,
    /// so "https://evil@op.example.com" would otherwise pass for "https://op.example.com".
    /// Without this check a document served on one issuer path, or reached by a redirect, answers
    /// for another issuer of the same host, and every token afterwards verifies against the wrong
    /// key set.
    /// </remarks>
    private static void RequireDeclaredIssuer(JsonElement document, Uri discoveryUri, Uri origin)
    {
        var declared = document.TryGetProperty("issuer", out var issuerElement)
                       && issuerElement.ValueKind == JsonValueKind.String
            ? issuerElement.GetString()
            : null;

        if (Uri.TryCreate(declared, UriKind.Absolute, out var declaredIssuer)
            && string.Equals(declaredIssuer.AbsoluteUri, origin.AbsoluteUri, StringComparison.Ordinal))
        {
            return;
        }

        throw new InvalidOperationException(
            $"The document at '{discoveryUri}' asserts the issuer '{declared}', not the '{origin}' "
            + "it was fetched for; accepting it would let one issuer of a host answer for another "
            + "(RFC 8414 Section 3.3).");
    }

    /// <summary>
    /// The document behind this URI decides which signatures verify, so its transport is part of
    /// the trust: over cleartext HTTP, whoever sits on the path substitutes a key and every token
    /// they sign afterwards validates.
    /// </summary>
    /// <param name="uri">The address about to be fetched.</param>
    /// <param name="what">What is being fetched, so a refusal names it.</param>
    /// <param name="allowLoopback">
    /// Whether cleartext over loopback is acceptable here. True for an address this host chose - a
    /// developer local issuer offers no path for anyone to sit on. False for one a remote document
    /// chose, where the exemption lets that document aim the receiver at its own loopback.
    /// </param>
    private static void RequireSecureTransport(Uri uri, string what, bool allowLoopback)
    {
        if (uri.Scheme == Uri.UriSchemeHttps)
            return;

        // Scheme first, then loopback: Uri.IsLoopback is true of "file:///keys.json" too, so a
        // check asking only about loopback lets a non-HTTP scheme past the transport rule.
        if (allowLoopback && uri.Scheme == Uri.UriSchemeHttp && uri.IsLoopback)
            return;

        throw new InvalidOperationException(
            $"Refusing to fetch {what} over '{uri.Scheme}' from '{uri}': a document fetched over "
            + "cleartext can be substituted in transit. Serve it over HTTPS, or use a loopback "
            + "address for local development.");
    }

    private static Uri DeriveWellKnownUri(string issuer)
        => new($"{JwksKeyResolutionOptions.NormaliseIssuer(issuer)}/.well-known/jwks.json");
}
