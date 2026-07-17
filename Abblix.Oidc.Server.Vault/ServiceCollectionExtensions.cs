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
/// Registers the HashiCorp Vault / OpenBao Transit custodian for the Abblix OIDC Server.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers Vault / OpenBao Transit as the custodian of the OIDC provider's keys and opens the tier choice
    /// that completes the wiring. This call is only the transport: it configures the typed
    /// <see cref="VaultTransitClient"/> against the Transit mount and carries the auth token. Which keys are used
    /// - and whether their private halves ever enter this process - is the tier call chained onto the returned
    /// builder, which must follow: a custodian without one fails at startup rather than silently falling back to
    /// the static keys in <c>OidcOptions</c>. Chain both calls AFTER the OIDC registration, which the tier call
    /// composes onto.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configureOptions">Configures the Vault address, auth token and Transit mount.</param>
    /// <returns>The builder whose tier call completes the wiring.</returns>
    /// <example>
    /// <code>
    /// services
    ///     .AddVaultCustodian(vault =&gt; configuration.GetSection("Vault").Bind(vault))
    ///     .HoldKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "oidc-sign" });
    /// </code>
    /// </example>
    public static IKeyCustodianBuilder AddVaultCustodian(
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

        // AddHttpClient above already registered the typed client as the IKeyCustodian, so this only opens the
        // tier choice on top of it.
        return services.AddCustodian();
    }
}
