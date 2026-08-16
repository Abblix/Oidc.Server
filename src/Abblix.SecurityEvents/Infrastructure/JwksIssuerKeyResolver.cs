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

using System.Collections.Concurrent;
using System.Net.Http.Json;
using System.Runtime.CompilerServices;
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
        var jwksUri = options.Value.ResolveJwksUri(issuer) ?? DeriveWellKnownUri(issuer);

        // The document behind this URI decides which signatures verify, so its transport is part
        // of the trust: over cleartext HTTP, whoever sits on the path substitutes a key and every
        // token they sign afterwards validates. Loopback stays permitted - a developer's local
        // issuer offers no path for anyone to sit on.
        if (jwksUri.Scheme != Uri.UriSchemeHttps && !jwksUri.IsLoopback)
        {
            throw new InvalidOperationException(
                $"Refusing to fetch signature verification keys over '{jwksUri.Scheme}' from '{jwksUri}': "
                + "a JWK Set fetched over cleartext can be substituted in transit. Serve it over HTTPS, "
                + "or use a loopback address for local development.");
        }

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

    private static Uri DeriveWellKnownUri(string issuer)
        => new($"{issuer.TrimEnd('/')}/.well-known/jwks.json");
}
