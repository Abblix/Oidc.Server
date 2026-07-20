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
}
