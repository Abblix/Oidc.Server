// Abblix OIDC Client Library
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

using Abblix.DependencyInjection;
using Abblix.Jwt;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.Features.Discovery;

/// <summary>
/// Registers the provider discovery feature.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the guard that stands in until the host chooses where the provider's metadata comes from.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    internal static IServiceCollection AddMetadataSourcePlaceholder(this IServiceCollection services)
    {
        // TryAdd, so a host that chose its source before calling the core keeps that choice.
        services.TryAddSingleton<IProviderMetadataProvider, MetadataSourceNotChosenProvider>();
        return services;
    }

    /// <summary>
    /// Reads the provider's endpoints from the discovery document it publishes.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configureOptions">A delegate that configures <see cref="DiscoveryOptions"/>.</param>
    /// <returns>The same collection, so calls chain.</returns>
    public static IServiceCollection AddDiscovery(
        this IServiceCollection services, Action<DiscoveryOptions> configureOptions)
    {
        services.Configure(configureOptions);
        services.AddHttpClient(DiscoveredMetadataProvider.HttpClientName);

        // A soft default, so a test or a host can substitute a clock before this call.
        services.TryAddSingleton(TimeProvider.System);

        // TryAdd, so a host that pinned metadata keys before this call keeps that choice.
        services.TryAddSingleton<ISignedMetadataVerifier, NoSignedMetadataVerifier>();

        // Replaces the not-chosen guard the core registers: this call IS the host making the choice.
        // Singleton because the cache is the point, a scoped provider would re-fetch per request.
        services.Replace(
            ServiceDescriptor.Singleton<IProviderMetadataProvider, DiscoveredMetadataProvider>());

        return services;
    }

    /// <summary>
    /// Requires the provider's discovery document to carry an RFC 8414 section 2.1 <c>signed_metadata</c>
    /// value that verifies against <paramref name="verificationKeys"/>, and lets the signed values take
    /// precedence over the published JSON.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="verificationKeys">
    /// The provider's metadata-signing keys, as the host obtained them - from the provider's documentation,
    /// an operator's hand, a configuration store. Not from the discovery document, which is the point.
    /// </param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// Only worth making when the host holds the keys independently of the document. A client that reads the
    /// document over TLS from its own issuer already has RFC 8414 section 6.2's assurance and gains nothing
    /// from a signature the same document vouches for. What this call answers is the case where the transport
    /// is not the provider: metadata through a registry, a mirror, a cache, or an intermediary the host does
    /// not own.
    ///
    /// It has a cost, and it is the same one pinning always has: a provider that rotates its metadata-signing
    /// key makes this client refuse the document until the host is reconfigured.
    /// </remarks>
    public static IServiceCollection AddSignedMetadataVerification(
        this IServiceCollection services, IReadOnlyCollection<JsonWebKey> verificationKeys)
    {
        if (verificationKeys.Count == 0)
            throw new ArgumentException(
                "Signed metadata verification was asked for without any key to verify against, which would "
                + "refuse every document the provider publishes.",
                nameof(verificationKeys));

        // Replaces the ignoring default: this call IS the host saying it holds keys. Replace rather than
        // TryAdd so the answer does not depend on whether this ran before or after AddDiscovery.
        services.Replace(ServiceDescriptor.Singleton<ISignedMetadataVerifier>(
            provider => provider.CreateService<SignedMetadataVerifier>(Dependency.Override(verificationKeys))));

        return services;
    }

    /// <summary>
    /// Takes the provider's endpoints from configuration, for a provider that publishes no discovery
    /// document.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="metadata">The provider's endpoints, as documented by that provider.</param>
    /// <returns>The same collection, so calls chain.</returns>
    public static IServiceCollection AddConfiguredMetadata(
        this IServiceCollection services, ProviderMetadata metadata)
    {
        services.TryAddSingleton(metadata);

        // Replaces the not-chosen guard the core registers: this call IS the host making the choice.
        services.Replace(
            ServiceDescriptor.Singleton<IProviderMetadataProvider, ConfiguredMetadataProvider>());

        return services;
    }
}
