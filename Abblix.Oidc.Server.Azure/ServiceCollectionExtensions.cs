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

namespace Abblix.Oidc.Server.Azure;

/// <summary>
/// Registers the Azure Key Vault custodian for the Abblix OIDC Server.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers Azure Key Vault as the custodian of the OIDC provider's keys and opens the tier choice that
    /// completes the wiring. This call is only the transport: it registers the vault client and its credential.
    /// Which keys are used - and whether their private halves ever enter this process - is the tier call chained
    /// onto the returned builder, which must follow: a custodian without one fails loud on first key use rather
    /// than silently falling back to the static keys in <c>OidcOptions</c>.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configureOptions">Configures the vault URI and the service-principal credentials.</param>
    /// <returns>The builder whose tier call completes the wiring.</returns>
    /// <example>
    /// <code>
    /// services
    ///     .AddAzureCustodian(azure =&gt; configuration.GetSection("Azure").Bind(azure))
    ///     .HoldKeysInCustodian(new CustodianHeldKeys { SigningKeyName = "oidc-sign" });
    /// </code>
    /// </example>
    public static IKeyCustodianBuilder AddAzureCustodian(
        this IServiceCollection services, Action<AzureKeyVaultOptions> configureOptions)
    {
        services.Configure(configureOptions);

        // Typed client so the Azure SDK's transport is the host's IHttpClientFactory pipeline, mirroring the Vault
        // package. The SDK sets absolute request URIs and authenticates via the credential, so the HttpClient needs
        // no base address or header configuration here. The SDK keeps one client for the vault, so this HttpClient is
        // held long-lived: disable handler rotation and let SocketsHttpHandler.PooledConnectionLifetime recycle
        // connections to pick up DNS changes, the pattern Microsoft recommends for a long-lived HttpClient.
        services
            .AddHttpClient<IKeyCustodian, AzureKeyVaultClient>()
            .ConfigurePrimaryHttpMessageHandler(provider =>
            {
                var options = provider.GetRequiredService<IOptions<AzureKeyVaultOptions>>();
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
