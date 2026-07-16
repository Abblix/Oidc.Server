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

using Abblix.Oidc.Server.Features.ExternalKeys;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Azure;

/// <summary>
/// Wires the Azure Key Vault custodian into the Abblix OIDC Server crypto seam and JWKS publishing.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Integrates Azure Key Vault as the OIDC provider's external key store: a signing key routes its signing to
    /// the vault and an encryption key its RSA-OAEP-256 unwrap, both addressed by the key's <c>kid</c> (the Key
    /// Vault key name), while the keys' public halves are fetched from the vault and published to the <c>/jwks</c>
    /// endpoint and local signature verification. Registers the vault client, wires the custodian into both
    /// crypto seams via <c>AddKeyCustodian</c>, and replaces the default key provider - so call this AFTER the
    /// OIDC registration for the last singular registration to win.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <param name="configureOptions">Configures the vault URI, service-principal credentials and key names.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection AddAzureExternalKeys(
        this IServiceCollection services, Action<AzureKeyVaultOptions> configureOptions)
    {
        services.Configure(configureOptions);

        // Typed client so the Azure SDK's transport is the host's IHttpClientFactory pipeline, mirroring the Vault
        // package. The SDK sets absolute request URIs and authenticates via the credential, so the HttpClient needs
        // no base address or header configuration here.
        services.AddHttpClient<AzureKeyVaultClient>();

        // Register the vault client as the external key store, then let the shared wiring route its private
        // operations through the crypto seam and publish its public halves at /jwks. This replaces the OIDC
        // default key provider, so call this after the OIDC registration to win the singular resolve.
        services.AddSingleton<IExternalKeyStore>(serviceProvider => serviceProvider.GetRequiredService<AzureKeyVaultClient>());
        services.AddExternalRsaKeys(serviceProvider =>
        {
            var options = serviceProvider.GetRequiredService<IOptions<AzureKeyVaultOptions>>().Value;
            return (options.SigningKeyName, options.EncryptionKeyName);
        });
        return services;
    }
}
