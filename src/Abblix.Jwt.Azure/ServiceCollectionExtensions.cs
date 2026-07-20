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

using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Azure.Core.Pipeline;
using Azure.Storage.Blobs;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.Azure;

/// <summary>
/// Registers the Azure Key Vault custodian for the Abblix OIDC Server.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>Names the HTTP client the blob ring rides, so it shares the package's pipeline conventions.</summary>
    private const string BlobRingClient = "Abblix.Jwt.Azure.KeyRing";

    /// <summary>
    /// Registers Azure Key Vault as the custodian of the OIDC provider's keys and opens the placement choice that
    /// completes the wiring. This call is only the transport: it registers the vault client and its credential.
    /// Which keys are used - and whether their private halves ever enter this process - is the placement call chained
    /// onto the returned builder, which must follow: a custodian without one fails loud on first key use rather
    /// than silently falling back to the static keys in <c>OidcOptions</c>.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configureOptions">Configures the vault URI and the service-principal credentials.</param>
    /// <returns>The builder whose placement call completes the wiring.</returns>
    /// <example>
    /// <code>
    /// services
    ///     .AddAzureCustodian(azure =&gt; configuration.GetSection("Azure").Bind(azure))
    ///     .UseKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "oidc-sign" });
    /// </code>
    /// </example>
    public static IKeyCustodianBuilder AddAzureCustodian(
        this IServiceCollection services, Action<AzureKeyVaultOptions> configureOptions)
    {
        // Validate at startup, not on first key use: a missing or relative vault URI is a deployment mistake, and
        // catching it here names the option rather than surfacing an opaque SDK error the first time a token is
        // signed. required guards a `new` the compiler sees; the config binder builds this by reflection, so the
        // URI can still arrive null and the check is what holds.
        services.AddOptions<AzureKeyVaultOptions>()
            .Configure(configureOptions)
            .Validate(
                options => options.KeyVaultUri is { IsAbsoluteUri: true },
                "AddAzureCustodian needs KeyVaultUri set to the vault endpoint, e.g. https://<name>.vault.azure.net/.")
            .ValidateOnStart();

        // Typed client so the Azure SDK's transport is the host's IHttpClientFactory pipeline, mirroring the Vault
        // package. The SDK sets absolute request URIs and authenticates via the credential, so the HttpClient needs
        // no base address or header configuration here. The SDK keeps one client for the vault, so this HttpClient is
        // held long-lived: disable handler rotation and let SocketsHttpHandler.PooledConnectionLifetime recycle
        // connections to pick up DNS changes, the pattern Microsoft recommends for a long-lived HttpClient.
        services
            .AddHttpClient<KeyVaultClient>()
            .ConfigurePrimaryHttpMessageHandler(provider =>
            {
                var options = provider.GetRequiredService<IOptions<AzureKeyVaultOptions>>();
                return new SocketsHttpHandler
                {
                    PooledConnectionLifetime = options.Value.PooledConnectionLifetime,
                };
            })
            .SetHandlerLifetime(Timeout.InfiniteTimeSpan);

        // TryAdd rather than the typed-client registration itself: AddHttpClient registers its client TRANSIENT,
        // so each of the four singletons that inject a custodian would get its own KeyVaultClient, and with
        // it its own DefaultAzureCredential, its own Entra token cache and its own per-key CryptographyClient
        // cache - defeating the caching this client exists for. It also let the library silently beat a host that
        // pre-registered its own custodian, which the repo's DI rule forbids.
        services.TryAddSingleton<IKeyCustodian>(provider => provider.GetRequiredService<KeyVaultClient>());

        return services.RequireKeyPlacement();
    }

    /// <summary>
    /// Keeps the ring of minted keys in an Azure Blob Storage container, using the same credential the custodian
    /// authenticates with.
    /// </summary>
    /// <param name="builder">The builder returned by <c>UseKeysInProcess</c>.</param>
    /// <param name="configureOptions">Configures the blob service endpoint and the container.</param>
    /// <returns>The service collection, for chaining.</returns>
    /// <remarks>
    /// It hangs off the minting placement rather than the service collection because a ring belongs to it and to
    /// no other: the placement where the vault holds every key has nothing to store.
    /// <para>
    /// Blob rather than a Key Vault secret, though the vault is already configured: a secret write has no
    /// conditional create, so two pods minting the same period would both succeed and each publish its own key. A
    /// blob upload takes <c>If-None-Match: *</c>, which is the insert-if-absent the ring needs. What lands there
    /// is a JWE sealed to the vault's key, so the container holds ciphertext and never a secret.
    /// </para>
    /// </remarks>
    public static IServiceCollection PersistRingToAzureBlob(
        this IMintedKeysBuilder builder,
        Action<AzureBlobKeyRingOptions> configureOptions)
    {
        var services = builder.Services;

        // Validated at startup for the same reason as the vault URI: a missing or relative endpoint is a
        // deployment mistake, and catching it here names the option instead of failing later inside the blob SDK.
        services.AddOptions<AzureBlobKeyRingOptions>()
            .Configure(configureOptions)
            .Validate(
                options => options.ServiceUri is { IsAbsoluteUri: true },
                "PersistRingToAzureBlob needs ServiceUri set to the blob endpoint, e.g. https://<account>.blob.core.windows.net.")
            .ValidateOnStart();

        // Named rather than typed, because the store takes a container client rather than an HttpClient. The
        // pipeline matters all the same: every other client in this package rides IHttpClientFactory, the README
        // promises it, and without it the ring gets none of the host's handlers or logging, and no
        // PooledConnectionLifetime to recycle connections for DNS changes.
        services
            .AddHttpClient(BlobRingClient)
            .ConfigurePrimaryHttpMessageHandler(provider =>
            {
                var options = provider.GetRequiredService<IOptions<AzureKeyVaultOptions>>();
                return new SocketsHttpHandler
                {
                    PooledConnectionLifetime = options.Value.PooledConnectionLifetime,
                };
            })
            .SetHandlerLifetime(Timeout.InfiniteTimeSpan);

        services.TryAddSingleton<IKeyRingStore>(provider =>
        {
            var ring = provider.GetRequiredService<IOptions<AzureBlobKeyRingOptions>>().Value;

            // The same credential chain the custodian uses: the ring is not a second identity to manage, and the
            // container is reached by whatever already reaches the vault.
            var credential = KeyVaultClient.BuildCredential(
                provider.GetRequiredService<IOptions<AzureKeyVaultOptions>>().Value);

            var httpClient = provider.GetRequiredService<IHttpClientFactory>().CreateClient(BlobRingClient);
            var options = new BlobClientOptions { Transport = new HttpClientTransport(httpClient) };

            var service = new BlobServiceClient(ring.ServiceUri, credential, options);

            // Override only the container client; the provider resolves the rest of the store's dependencies,
            // the logger included, so none of them is restated here.
            return provider.CreateService<BlobKeyRingStore>(
                Dependency.Override(service.GetBlobContainerClient(ring.Container)));
        });

        return services;
    }
}
