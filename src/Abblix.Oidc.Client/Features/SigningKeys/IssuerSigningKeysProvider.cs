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

using System.Net.Http.Json;
using System.Text.Json;
using Abblix.Jwt;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Internals;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.SigningKeys;

/// <summary>
/// Reads the provider's key set from the address its metadata names, keeps it, and re-reads it when a token
/// names a key that is not held.
/// </summary>
public sealed class IssuerSigningKeysProvider : IIssuerSigningKeysProvider
{
    /// <summary>
    /// The name of the <see cref="HttpClient"/> this provider resolves from <see cref="IHttpClientFactory"/>.
    /// </summary>
    public const string HttpClientName = "Abblix.Oidc.Client.SigningKeys";

    /// <summary>
    /// The value of a key's <c>use</c> member that marks it as a signature-verification key, per RFC 7517.
    /// </summary>
    private const string SignatureUsage = "sig";

    private readonly IProviderMetadataProvider _metadataProvider;
    private readonly IHttpClientFactory _httpClientFactory;
    private readonly TimeProvider _timeProvider;
    private readonly SigningKeysOptions _options;
    private readonly RefreshingCache<IReadOnlyCollection<JsonWebKey>> _cache;

    /// <summary>
    /// The moment the last read triggered by an unknown key happened, which bounds how often the next one may.
    /// </summary>
    private DateTimeOffset? _lastRefreshForUnknownKey;

    /// <summary>
    /// Creates the provider.
    /// </summary>
    public IssuerSigningKeysProvider(
        IProviderMetadataProvider metadataProvider,
        IHttpClientFactory httpClientFactory,
        TimeProvider timeProvider,
        IOptions<SigningKeysOptions> options)
    {
        _metadataProvider = metadataProvider;
        _httpClientFactory = httpClientFactory;
        _timeProvider = timeProvider;
        _options = options.Value;
        _cache = new RefreshingCache<IReadOnlyCollection<JsonWebKey>>(timeProvider);
    }

    /// <inheritdoc />
    public async Task<IReadOnlyCollection<JsonWebKey>> GetSigningKeysAsync(
        string? keyId, CancellationToken cancellationToken = default)
    {
        var keys = await _cache.GetAsync(FetchAsync, _options.CacheLifetime, cancellationToken);

        if (keyId is null)
            return keys;

        if (TrySelect(keys, keyId, out var named))
            return named;

        // The token names a key the client has not seen. That is what a rotation looks like from here, so
        // read the set again rather than rejecting - but no more often than the floor allows, because this
        // path is driven by whoever presents the token.
        if (!MayRefreshForUnknownKey())
            return keys;

        _lastRefreshForUnknownKey = _timeProvider.GetUtcNow();
        keys = await _cache.GetAsync(FetchAsync, _options.CacheLifetime, forceRefresh: true, cancellationToken);

        // Still unknown after the re-read: return everything held and let signature verification make the
        // final call. Deciding "no such key" here would turn a key the provider serves but does not label the
        // way this client expects into a silent authentication failure.
        return TrySelect(keys, keyId, out named) ? named : keys;
    }

    private bool MayRefreshForUnknownKey()
        => _lastRefreshForUnknownKey is not { } lastRefresh ||
           _options.MinimumRefreshInterval <= _timeProvider.GetUtcNow() - lastRefresh;

    private static bool TrySelect(
        IReadOnlyCollection<JsonWebKey> keys, string keyId, out IReadOnlyCollection<JsonWebKey> selected)
    {
        var named = keys.Where(key => key.KeyId == keyId).ToArray();
        selected = named;
        return named.Length > 0;
    }

    private async Task<IReadOnlyCollection<JsonWebKey>> FetchAsync(CancellationToken cancellationToken)
    {
        var metadata = await _metadataProvider.GetMetadataAsync(cancellationToken);

        if (metadata.JsonWebKeySetUri is not { } keySetUri)
            throw new SigningKeysException(
                $"The OpenID Provider '{metadata.Issuer}' names no key set, so a signature it makes cannot be "
                + "verified.");

        JsonWebKeySet? keySet;
        try
        {
            var httpClient = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await httpClient.GetAsync(keySetUri, cancellationToken);
            response.EnsureSuccessStatusCode();
            keySet = await response.Content.ReadFromJsonAsync<JsonWebKeySet>(cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException)
        {
            throw new SigningKeysException(
                $"Failed to read the key set of OpenID Provider '{metadata.Issuer}' from '{keySetUri}'.",
                exception);
        }

        var keys = keySet?.Keys ?? [];

        // Keys that carry no public half cannot verify anything, and a key the provider marks for encryption
        // must not be pressed into signature verification: reusing a key across purposes is exactly what the
        // `use` member exists to prevent.
        var signingKeys = keys
            .Where(key => key.HasPublicKey && key.Usage is null or SignatureUsage)
            .ToArray();

        if (signingKeys.Length == 0)
            throw new SigningKeysException(
                $"The key set of OpenID Provider '{metadata.Issuer}' at '{keySetUri}' holds no key usable for "
                + "signature verification.");

        return signingKeys;
    }
}
