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

using Abblix.Jwt;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.Features.SigningKeys;

/// <summary>
/// Registers the reader of the provider's signing keys.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the source of the keys that verify signatures made by the OpenID Provider.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    public static IServiceCollection AddSigningKeys(this IServiceCollection services)
    {
        services.AddHttpClient(IssuerSigningKeysProvider.HttpClientName);

        // A soft default, so a test or a host can substitute a clock before this call.
        services.TryAddSingleton(TimeProvider.System);

        // Singleton because the key set is cached across requests. The contract is registered with TryAdd,
        // so a host running many replicas can supply an implementation whose cache and refresh floor are
        // shared across them - see the remarks on SigningKeysOptions.MinimumRefreshInterval.
        services.TryAddSingleton<IIssuerSigningKeysProvider, IssuerSigningKeysProvider>();

        return services;
    }

    /// <summary>
    /// Uses a fixed set of verification keys held by the host, instead of reading the provider's key set.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="keys">The provider's verification keys, as published by that provider.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// For a provider that publishes no key set, a deployment that cannot reach the one it publishes, or an
    /// operator who wants the keys pinned. The trade is that a rotation by the provider now needs a
    /// reconfiguration here, so this is a choice rather than a default.
    /// </remarks>
    public static IServiceCollection AddConfiguredSigningKeys(
        this IServiceCollection services, IReadOnlyCollection<JsonWebKey> keys)
    {
        // Replaces the reader registered by AddSigningKeys: this call IS the host making the choice.
        services.Replace(ServiceDescriptor.Singleton<IIssuerSigningKeysProvider>(
            _ => new ConfiguredSigningKeysProvider(keys)));

        return services;
    }
}
