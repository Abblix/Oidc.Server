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
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Vault;

/// <summary>
/// Registers the HashiCorp Vault / OpenBao Transit custodian for the Abblix OIDC Server.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers Vault / OpenBao Transit as the custodian of the OIDC provider's keys and opens the tier choice
    /// that completes the wiring. This call is only the transport: it points a client at the Vault server and
    /// carries the auth token. Which keys are used - and whether their private halves ever enter this process - is
    /// the tier call chained onto the returned builder, which must follow: a custodian without one fails at
    /// startup rather than silently falling back to the static keys in <c>OidcOptions</c>. Chain both calls AFTER
    /// the OIDC registration, which the tier call composes onto.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configureOptions">Configures the Vault address, auth token and Transit mount.</param>
    /// <returns>The builder whose tier call completes the wiring.</returns>
    /// <example>
    /// <code>
    /// services
    ///     .AddVaultCustodian(vault =&gt; configuration.GetSection("Vault").Bind(vault))
    ///     .UseKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "oidc-sign" });
    /// </code>
    /// </example>
    public static IKeyCustodianBuilder AddVaultCustodian(
        this IServiceCollection services,
        Action<VaultTransitOptions> configureOptions)
    {
        services.Configure(configureOptions);
        services.AddVaultTransport();

        // Singular contract, TryAdd so a host that brought its own custodian keeps it, as the repo's DI rule
        // requires.
        services.TryAddSingleton<IKeyCustodian, TransitCustodian>();

        return services.AddCustodian();
    }

    /// <summary>
    /// Keeps the ring of minted keys in this Vault's KV version 2 engine, on the same server that holds the key
    /// protecting them.
    /// </summary>
    /// <param name="builder">The builder returned by <c>UseKeysInProcess</c>.</param>
    /// <param name="configureOptions">Configures the KV mount and the path the ring lives under.</param>
    /// <returns>The service collection, for chaining.</returns>
    /// <remarks>
    /// It hangs off the minting tier rather than the service collection because a ring belongs to that tier and to
    /// no other: the tier where the custodian holds every key has nothing to store.
    /// <para>
    /// The engine must be KV v2. Its <c>cas=0</c> write is the insert-if-absent the ring is built on, and it is
    /// what makes exactly one pod mint a period without a lock service. What lands there is a JWE the server
    /// sealed to the custodian's key, so the engine holds ciphertext and never a secret.
    /// </para>
    /// </remarks>
    public static IServiceCollection PersistRingToVaultKeyValue(
        this IMintedKeysBuilder builder,
        Action<VaultKeyValueOptions>? configureOptions = null)
    {
        var services = builder.Services;
        services.Configure(configureOptions ?? (_ => { }));
        services.AddVaultTransport();

        // Singular contract, pinned so a host that brings its own ring keeps it: see the custodian registration.
        services.TryAddSingleton<IKeyRingStore, KeyValueStore>();

        return services;
    }

    /// <summary>
    /// Registers the one named client both engines resolve, once however many of them are wired.
    /// </summary>
    /// <remarks>
    /// The ring rides the same server and token as the custodian - one Vault holds both the key that protects the
    /// ring and the ring itself - so a second client would only mean a second connection pool to the same place,
    /// and a second copy of the auth, redaction and lifetime settings to keep in step. Handler rotation is off and
    /// <see cref="SocketsHttpHandler.PooledConnectionLifetime"/> recycles the connections underneath instead,
    /// because the consumers hold their client for their own lifetime - the pattern Microsoft recommends for a
    /// long-lived HttpClient.
    /// </remarks>
    private static void AddVaultTransport(this IServiceCollection services)
    {
        // AddHttpClient appends its configuration rather than replacing it, so a second call would run the whole
        // chain twice - two token handlers on the request, redaction applied twice. The token handler's own
        // registration, the first thing this does, is the mark that the transport has already been wired.
        if (services.Any(descriptor => descriptor.ServiceType == typeof(TokenHandler)))
            return;

        services.TryAddTransient<TokenHandler>();

        services.AddHttpClient(Transport.ClientName, (provider, http) =>
        {
            // The address stops at the server root: a mount belongs to an engine, and Transit and KV are on
            // different ones, so each spells its own into every path.
            var options = provider.GetRequiredService<IOptions<VaultTransitOptions>>().Value;
            http.BaseAddress = new Uri($"{options.Address.TrimEnd('/')}/v1/");
        })
        .AddHttpMessageHandler<TokenHandler>()

        // The token is a bearer credential that can sign as this provider. IHttpClientFactory's own logging
        // writes request headers at Trace and redacts nothing by default, so debugging a Vault connectivity
        // problem - exactly when Trace gets turned on - would print it in the clear.
        .RedactLoggedHeaders([TokenHandler.TokenHeaderName])
        .ConfigurePrimaryHttpMessageHandler(provider =>
        {
            var options = provider.GetRequiredService<IOptions<VaultTransitOptions>>();
            return new SocketsHttpHandler
            {
                PooledConnectionLifetime = options.Value.PooledConnectionLifetime,
            };
        })
        .SetHandlerLifetime(Timeout.InfiniteTimeSpan);
    }
}
