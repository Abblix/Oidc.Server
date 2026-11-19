// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Utils;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// The metadata documents fetched for client identifier URLs, each read and held for as long as its response allows.
/// </summary>
/// <param name="logger">Records a document refused, and a copy served past its lifetime.</param>
/// <param name="fetcher">Fetches a document.</param>
/// <param name="scopes">Opens the container a document is read in, since what the server supports is answered by
/// scoped services.</param>
/// <param name="cache">Holds a read document.</param>
/// <param name="options">The cache bounds, read on each fetch.</param>
/// <param name="clock">Dates a fetch.</param>
internal sealed partial class HeldMetadataDocuments(
    ILogger<HeldMetadataDocuments> logger,
    ClientIdMetadataDocumentFetcher fetcher,
    IServiceScopeFactory scopes,
    IMemoryCache cache,
    IOptionsMonitor<OidcOptions> options,
    TimeProvider clock)
{
    /// <summary>
    /// How long the outcome of one fetch answers the lookups that follow it.
    /// </summary>
    /// <remarks>
    /// An authorization request looks its client up more than once, and a refused document would otherwise be fetched
    /// for each lookup, by anybody naming its URL. Section 6.2 lets the server "implement rate limiting or other measures
    /// to avoid repeatedly fetching a Client ID Metadata Document URL", and this hold is that: long enough to answer the
    /// lookups of one request, too short to serve a refusal as the client's metadata.
    /// </remarks>
    internal static readonly TimeSpan RepeatedLookupHold = TimeSpan.FromSeconds(1);

    // One fetch of a URL for all the requests naming it at once and the lookups that follow within the hold
    private readonly CoalescingLoader<string, HeldMetadataDocument?> _fetches = new(clock, StringComparer.Ordinal);

    /// <summary>
    /// The document of <paramref name="clientId"/> as read, fetched when none is held or the one held is past its
    /// lifetime; null when it cannot be had or is refused.
    /// </summary>
    /// <param name="clientId">The client identifier URL, as the request carries it.</param>
    /// <param name="url">The URL to fetch it from.</param>
    public async Task<HeldMetadataDocument?> GetAsync(string clientId, Uri url)
    {
        var key = CacheKey(clientId);
        var held = cache.Get<HeldMetadataDocument>(key);
        if (held is not null && clock.GetUtcNow() < held.FreshUntil)
            return held;

        return await _fetches.LoadAsync(clientId, _ => FetchAsync(key, clientId, url, held), RepeatedLookupHold);
    }

    private async Task<HeldMetadataDocument?> FetchAsync(
        string key,
        string clientId,
        Uri url,
        HeldMetadataDocument? previous)
    {
        var settings = options.CurrentValue.ClientIdMetadataDocuments;
        var fetchedAt = clock.GetUtcNow();

        var fetched = await fetcher.FetchAsync(url);
        var result = fetched.TryGetSuccess(out var document)
            ? (await ReadAsync(clientId, document)).MapSuccess(
                metadata => new HeldMetadataDocument(metadata, fetchedAt + document.Lifetime))
            : fetched.GetFailure();

        if (result.TryGetSuccess(out var read))
        {
            // A response that may not be held answers this request alone: section 6.2 has the server "respect HTTP
            // cache headers", no-store among them. One that may is kept until the host's maximum has passed since it
            // was fetched, so a fetch failing for a reason that may pass can still be answered with it
            if (read.FreshUntil > fetchedAt)
                cache.Set(key, read, new MemoryCacheEntryOptions
                {
                    AbsoluteExpiration = fetchedAt + settings.MaximumCacheDuration,
                    Size = 1,
                });
            else
                cache.Remove(key);

            return read;
        }

        var failure = result.GetFailure();

        // Section 6.1: "An authorization server SHOULD NOT discard previously cached valid client metadata on transient
        // failures"
        if (failure.MayPass && previous is not null)
        {
            LogHeldCopyServed(clientId, failure.Reason);
            return previous;
        }

        if (!failure.MayPass)
            LogDocumentRefused(clientId, failure.Reason);

        // Section 6.2: the server "MUST NOT cache documents which are invalid or malformed", so a document refused now
        // is not served from what was held of it before. Section 6.1 also says a terminal failure "caused by a
        // client_id mismatch SHOULD invalidate the client's outstanding refresh tokens immediately"; this server does
        // not, as it keeps no cutoff for every token of one client: the client is refused at the token endpoint while
        // its document is refused, and its refresh tokens are served again once a valid document returns
        cache.Remove(key);
        return null;
    }

    private async Task<Result<Model.ClientRegistrationRequest, MetadataDocumentFailure>> ReadAsync(
        string clientId,
        FetchedDocument document)
    {
        await using var scope = scopes.CreateAsyncScope();
        return ActivatorUtilities.CreateInstance<ClientIdMetadataDocumentReader>(scope.ServiceProvider)
            .Read(clientId, document.Content);
    }

    private static string CacheKey(string clientId)
        => $"{nameof(Abblix)}.{nameof(Oidc)}.{nameof(Server)}.{nameof(ClientIdMetadataDocuments)}:{clientId}";
}
