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

        // Replaces the not-chosen guard the core registers: this call IS the host making the choice.
        // Singleton because the cache is the point, a scoped provider would re-fetch per request.
        services.Replace(
            ServiceDescriptor.Singleton<IProviderMetadataProvider, DiscoveredMetadataProvider>());

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
