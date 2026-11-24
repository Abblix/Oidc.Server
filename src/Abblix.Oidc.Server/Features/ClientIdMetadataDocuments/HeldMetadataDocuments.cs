// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Text.Json.Nodes;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
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
    // One fetch of a URL by one rule for the lookups naming it by that rule while it runs. Its outcome answers none that
    // starts after it ends: section 6.2 has the server "MUST NOT cache error responses", so a refused document is
    // fetched again on the next lookup
    private readonly CoalescingLoader<string, Result<HeldMetadataDocument, MetadataDocumentFailure>> _fetches = new(clock, StringComparer.Ordinal);

    /// <summary>
    /// The document of <paramref name="clientId"/> as read, fetched when none is held or the one held is past its
    /// lifetime; the failure when it cannot be had or is refused.
    /// </summary>
    /// <param name="clientId">The client identifier URL, as the request carries it.</param>
    /// <param name="url">The URL to fetch it from.</param>
    /// <param name="rule">The rule the fetch is held to. A document fetched by one rule is held apart from one fetched
    /// by the other and never answers a lookup made by it, so a name reaching loopback for one tenant is reached afresh,
    /// and refused, for a tenant whose fetch may not.</param>
    public async Task<Result<HeldMetadataDocument, MetadataDocumentFailure>> GetAsync(string clientId, Uri url, OutboundAddressRule rule)
    {
        var key = CacheKey(clientId, rule);
        var held = cache.Get<HeldMetadataDocument>(key);
        if (held is not null && clock.GetUtcNow() < held.FreshUntil)
            return held;

        return await _fetches.LoadAsync(key, _ => FetchAsync(key, clientId, url, rule, held), TimeSpan.Zero);
    }

    private async Task<Result<HeldMetadataDocument, MetadataDocumentFailure>> FetchAsync(
        string key,
        string clientId,
        Uri url,
        OutboundAddressRule rule,
        HeldMetadataDocument? previous)
    {
        var settings = options.CurrentValue.ClientIdMetadataDocuments;
        var fetchedAt = clock.GetUtcNow();

        Result<FetchedDocument, MetadataDocumentFailure> fetched;
        using (SpecialPurposeFetches.Enter(rule))
            fetched = await fetcher.FetchAsync(url);
        var result = fetched.TryGetSuccess(out var document)
            ? (await ReadAsync(clientId, document)).MapSuccess(
                _ => new HeldMetadataDocument(document.Content.ToJsonString(), fetchedAt + document.Lifetime))
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
        return failure;
    }

    /// <summary>
    /// The registration metadata <paramref name="document"/> describes the client <paramref name="clientId"/> with at
    /// <paramref name="tenant"/>, or why it describes none there.
    /// </summary>
    /// <remarks>
    /// Section 5 has the server "select one of the values ... that it supports", and a method the tenant refuses, as
    /// tls_client_auth where it lists no certificate authority, is not one it supports, so the authentication method,
    /// and the grant types depending on it, are chosen among the methods the tenant admits.
    /// </remarks>
    public async Task<Result<Model.ClientRegistrationRequest, MetadataDocumentFailure>> ReadAtAsync(
        TenantDefinition tenant,
        string clientId,
        HeldMetadataDocument document)
    {
        await using var scope = scopes.CreateAsyncScope();
        var offered = Offered(scope.ServiceProvider);
        var admitted = TenantClientAuthenticationMethods.Admitted(tenant, offered);
        var read = ReaderIn(scope.ServiceProvider)
            .Read(clientId, JsonNode.Parse(document.Content)!.AsObject(), admitted);

        // The reader speaks of the methods it was handed as the server's, so a refusal names the ones this tenant
        // refuses of those the server offers, and why
        var refusedHere = offered.Except(admitted, StringComparer.Ordinal).ToArray();
        if (refusedHere.Length == 0 || !read.TryGetFailure(out var failure))
            return read;

        var why = refusedHere.Select(method => $"{method}: {TenantClientAuthenticationMethods.WhyRefused(tenant, method)}");
        return failure with { Reason = $"{failure.Reason}; this tenant refuses {string.Join("; ", why)}" };
    }

    private async Task<Result<Model.ClientRegistrationRequest, MetadataDocumentFailure>> ReadAsync(
        string clientId,
        FetchedDocument document)
    {
        // Judged against every method the server offers, so a document is held or refused alike for every tenant
        await using var scope = scopes.CreateAsyncScope();
        return ReaderIn(scope.ServiceProvider).Read(clientId, document.Content, Offered(scope.ServiceProvider));
    }

    private static string[] Offered(IServiceProvider services)
        => services.GetRequiredService<IClientAuthenticator>().ClientAuthenticationMethodsSupported.ToArray();

    private static ClientIdMetadataDocumentReader ReaderIn(IServiceProvider services)
        => ActivatorUtilities.CreateInstance<ClientIdMetadataDocumentReader>(services);

    // The rule's name stands before the colon, so no client identifier makes the key of one rule the key of the other
    private static string CacheKey(string clientId, OutboundAddressRule rule)
        => $"{nameof(Abblix)}.{nameof(Oidc)}.{nameof(Server)}.{nameof(ClientIdMetadataDocuments)}.{rule}:{clientId}";
}
