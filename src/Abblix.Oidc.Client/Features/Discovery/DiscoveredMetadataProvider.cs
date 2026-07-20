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
using Abblix.Oidc.Client.Internals;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Client.Features.Discovery;

/// <summary>
/// Fetches the provider's discovery document over HTTP, verifies its issuer and caches it for the configured
/// lifetime.
/// </summary>
public sealed class DiscoveredMetadataProvider : IProviderMetadataProvider
{
    /// <summary>
    /// The name of the <see cref="HttpClient"/> this provider resolves from <see cref="IHttpClientFactory"/>.
    /// A host tunes discovery transport (proxy, timeout, handler chain) by configuring this name.
    /// </summary>
    public const string HttpClientName = "Abblix.Oidc.Client.ProviderDiscovery";

    /// <summary>
    /// The well-known path the discovery document is published under, per OpenID Connect Discovery 1.0.
    /// </summary>
    private const string WellKnownPath = ".well-known/openid-configuration";

    /// <summary>
    /// The separator between URI path segments. Named rather than written inline so that the address-building
    /// below reads as URI composition instead of string surgery.
    /// </summary>
    private const char UriPathSeparator = '/';

    private readonly IHttpClientFactory _httpClientFactory;
    private readonly DiscoveryOptions _options;
    private readonly RefreshingCache<ProviderMetadata> _cache;

    /// <summary>
    /// Creates the provider.
    /// </summary>
    public DiscoveredMetadataProvider(
        IHttpClientFactory httpClientFactory,
        TimeProvider timeProvider,
        IOptions<DiscoveryOptions> options)
    {
        _httpClientFactory = httpClientFactory;
        _options = options.Value;
        _cache = new RefreshingCache<ProviderMetadata>(timeProvider);
    }

    /// <inheritdoc />
    public Task<ProviderMetadata> GetMetadataAsync(CancellationToken cancellationToken = default)
        => _cache.GetAsync(FetchAsync, _options.MetadataCacheLifetime, cancellationToken);

    private async Task<ProviderMetadata> FetchAsync(CancellationToken cancellationToken)
    {
        var address = ResolveMetadataAddress();

        ProviderMetadata? metadata;
        try
        {
            var httpClient = _httpClientFactory.CreateClient(HttpClientName);
            using var response = await httpClient.GetAsync(address, cancellationToken);
            response.EnsureSuccessStatusCode();
            metadata = await response.Content.ReadFromJsonAsync<ProviderMetadata>(cancellationToken);
        }
        catch (Exception exception) when (exception is HttpRequestException or JsonException)
        {
            throw new ProviderMetadataException(
                $"Failed to read the OpenID Provider metadata from '{address}'.", exception);
        }

        if (metadata is null)
            throw new ProviderMetadataException($"The OpenID Provider metadata at '{address}' was empty.");

        ValidateIssuer(metadata, address);
        return metadata;
    }

    private Uri ResolveMetadataAddress()
    {
        if (_options.MetadataAddress is { } explicitAddress)
            return explicitAddress;

        var authority = _options.Authority
            ?? throw new ProviderMetadataException(
                $"Neither {nameof(DiscoveryOptions.Authority)} nor {nameof(DiscoveryOptions.MetadataAddress)} "
                + "is configured, so there is no provider to discover.");

        // A relative path combines against the authority's directory, so an authority that carries a path
        // segment (a multi-tenant provider) would lose that segment unless the base ends in a separator.
        var authorityAsDirectory = authority.AbsoluteUri.EndsWith(UriPathSeparator)
            ? authority
            : new Uri(authority.AbsoluteUri + UriPathSeparator);

        return new Uri(authorityAsDirectory, WellKnownPath);
    }

    /// <summary>
    /// Enforces the issuer check of OpenID Connect Discovery 1.0 section 4.3: the issuer the document claims
    /// must be the authority the document was fetched from.
    /// </summary>
    /// <remarks>
    /// Without this check a provider that is able to serve a document at one authority could name any issuer
    /// it likes, and every later token validation would then be measured against that borrowed name.
    /// </remarks>
    private void ValidateIssuer(ProviderMetadata metadata, Uri address)
    {
        // Nothing to compare against when the host configured only an explicit metadata address: it has named
        // the document's location directly, so the authority is whatever that document declares.
        if (_options.Authority is not { } authority)
            return;

        // Compared as URIs rather than as text: a provider is free to declare its issuer with or without the
        // trailing slash, and both forms name the same authority. Anything else is a mismatch.
        if (!Uri.TryCreate(metadata.Issuer, UriKind.Absolute, out var declaredIssuer) || declaredIssuer != authority)
        {
            throw new ProviderMetadataException(
                $"The OpenID Provider metadata at '{address}' declares issuer '{metadata.Issuer}', "
                + $"which does not match the configured authority '{authority}'.");
        }
    }
}
