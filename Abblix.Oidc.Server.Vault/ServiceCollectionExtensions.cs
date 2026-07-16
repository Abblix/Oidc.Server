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
using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Vault;

/// <summary>
/// Wires the HashiCorp Vault / OpenBao Transit custodian into the Abblix OIDC Server crypto seam and JWKS
/// publishing.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Integrates Vault / OpenBao Transit as the OIDC provider's external key store: a signing key routes its
    /// signing to Vault and an encryption key its RSA-OAEP-256 unwrap, both addressed by the key's <c>kid</c>
    /// (the Transit key name), while the keys' public halves are fetched from Transit and published to the
    /// <c>/jwks</c> endpoint and local signature verification. Configures the typed <see cref="VaultTransitClient"/>,
    /// wires the custodian into both crypto seams via <c>AddKeyCustodian</c>, and replaces the default key
    /// provider - so call this AFTER the OIDC registration for the last singular registration to win.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configureOptions">Configures the Vault address, auth token, Transit mount and key names.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddVaultExternalKeys(
        this IServiceCollection services,
        Action<VaultTransitOptions> configureOptions)
    {
        services.Configure(configureOptions);

        // Typed client pointed at the Transit mount, carrying the auth token header. Options are read at client
        // creation so the configured address and token drive the base address and header. The external-key store is
        // a singleton, so this client is held long-lived: rather than per-call CreateClient, disable handler rotation
        // and let SocketsHttpHandler.PooledConnectionLifetime recycle connections to pick up DNS changes, the pattern
        // Microsoft recommends for a long-lived HttpClient.
        services.AddHttpClient<IKeyCustodian, VaultTransitClient>((provider, http) =>
        {
            var options = provider.GetRequiredService<IOptions<VaultTransitOptions>>().Value;
            http.BaseAddress = new Uri($"{options.Address.TrimEnd('/')}/v1/{options.TransitMount}/");
            if (!string.IsNullOrWhiteSpace(options.Token))
                http.DefaultRequestHeaders.Add("X-Vault-Token", options.Token);
        })
        .ConfigurePrimaryHttpMessageHandler(provider =>
        {
            var options = provider.GetRequiredService<IOptions<VaultTransitOptions>>();
            return new SocketsHttpHandler
            {
                PooledConnectionLifetime = options.Value.PooledConnectionLifetime,
            };
        })
        .SetHandlerLifetime(Timeout.InfiniteTimeSpan);

        services.AddExternalKeys(serviceProvider =>
        {
            var options = serviceProvider.GetRequiredService<IOptions<VaultTransitOptions>>().Value;

            return new ExternalKeyConfiguration(
                options.SigningKeyName,
                options.SigningAlgorithm,
                options.EncryptionKeyName,
                options.EncryptionAlgorithm);
        });
        return services;
    }
}
