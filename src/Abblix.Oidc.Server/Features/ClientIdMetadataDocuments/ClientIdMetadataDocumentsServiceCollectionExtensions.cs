// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using System.Diagnostics.CodeAnalysis;

namespace Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;

/// <summary>
/// Opts the server into OAuth Client ID Metadata Documents.
/// </summary>
public static class ClientIdMetadataDocumentsServiceCollectionExtensions
{
    /// <summary>
    /// Accepts a client that identifies itself by an <c>https</c> URL and publishes its metadata there
    /// (draft-ietf-oauth-client-id-metadata-document): the server fetches the document the first time the client is
    /// named, holds it as its response allows, and judges it as it judges a dynamic client registration. The discovery
    /// document then advertises <c>client_id_metadata_document_supported</c>.
    /// </summary>
    /// <param name="builder">The server's registration, which this extends.</param>
    /// <returns>The same builder, so further features can be added.</returns>
    /// <remarks>
    /// A client the host configured or registered under the same URL is served as configured, without a fetch. The
    /// client store is wrapped as it is registered when this is called, so a host registering its own
    /// <see cref="IClientInfoProvider"/> does it first; one registered afterwards is refused at startup. What a client so
    /// resolved may ask for is bounded by <see cref="OidcOptions.NewClientOptions"/>, and which URLs are fetched, how
    /// much of a document is read and how long it is held by <see cref="OidcOptions.ClientIdMetadataDocuments"/>. The
    /// fetch takes the outbound HTTP client named <see cref="ClientIdMetadataDocumentTransport.HttpClientName"/>, whose
    /// SSRF validation follows <see cref="SecureHttpFetchOptions"/>.
    /// <para>
    /// Every such client is one nobody reviewed, so the consent screen is the end user's only protection. A host that
    /// grants every client everything it asks for (<see cref="ConsentsServiceCollectionExtensions.AddConsentGrantedForEveryClient"/>)
    /// and sets no <see cref="ClientIdMetadataDocumentOptions.AllowedClientIdPrefixes"/> would let any URL obtain the
    /// end user's tokens unseen, so it does not start.
    /// </para>
    /// </remarks>
    [Experimental(ClientIdMetadataDocumentsExperiment.DiagnosticId, UrlFormat = ClientIdMetadataDocumentsExperiment.UrlFormat)]
    public static IOidcServerBuilder AddClientIdMetadataDocuments(this IOidcServerBuilder builder)
    {
        var services = builder.Services;

        // Wrapping the store twice would fetch every document twice over
        if (services.Any(descriptor => descriptor.ServiceType == typeof(HeldMetadataDocuments)))
            return builder;

        services.PostConfigure<OidcOptions>(options => options.ClientIdMetadataDocuments.Enabled = true);
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ClientIdMetadataDocumentOptionsValidator>());

        services.AddSsrfHttpClient(ClientIdMetadataDocumentTransport.HttpClientName, (serviceProvider, client) =>
            client.Timeout = serviceProvider.GetRequiredService<IOptions<OidcOptions>>().Value
                .ClientIdMetadataDocuments.FetchTimeout);

        // The registration checks a document passes take the host's limits on a new client, which dynamic registration
        // registers the same way when the host opens it
        services.TryAddTransient(serviceProvider =>
            serviceProvider.GetRequiredService<IOptions<OidcOptions>>().Value.NewClientOptions);

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<ClientIdMetadataDocumentFetcher>();
        // A cache of their own, so the number of documents held is bounded whatever the host's cache allows: the URLs
        // are chosen by whoever sends a request
        services.TryAddKeyedSingleton<IMemoryCache>(
            typeof(HeldMetadataDocuments),
            (serviceProvider, _) => new MemoryCache(new MemoryCacheOptions
            {
                SizeLimit = serviceProvider.GetRequiredService<IOptions<OidcOptions>>().Value
                    .ClientIdMetadataDocuments.MaxHeldDocuments,
            }));
        services.TryAddSingleton(serviceProvider => serviceProvider.CreateService<HeldMetadataDocuments>(
            Dependency.Override(provider =>
                provider.GetRequiredKeyedService<IMemoryCache>(typeof(HeldMetadataDocuments)))));
        services.Decorate<IClientInfoProvider, ClientIdMetadataDocumentClients>();

        services.AddOptions<ClientIdMetadataDocumentsWiring>()
            .Configure<IServiceProvider>((wiring, provider) =>
            {
                wiring.StoreResolvesDocuments = provider.GetService<IClientInfoProvider>() is ClientIdMetadataDocumentClients;

                using var scope = provider.CreateScope();
                wiring.IssuerSent = scope.ServiceProvider.GetService<IAuthorizationMetadataProvider>()
                    is not { AuthorizationResponseIssParameterSupported: false };

                // Refused rather than ignored for this transport: the flag decides the SSRF handler every outbound
                // client shares, and a document's URIs are fetched by the key, request and logout clients as well
                wiring.PrivateNetworksBlocked =
                    provider.GetRequiredService<IOptions<SecureHttpFetchOptions>>().Value.BlockPrivateNetworks;

                wiring.ConsentGrantedToAnyUrl = GrantsConsentToEveryClient(services) &&
                    provider.GetRequiredService<IOptions<OidcOptions>>().Value
                        .ClientIdMetadataDocuments.AllowedClientIdPrefixes is null;
            })
            .Validate(wiring => wiring.StoreResolvesDocuments, ClientIdMetadataDocumentsWiring.StoreReplacedMessage)
            .Validate(wiring => wiring.IssuerSent, ClientIdMetadataDocumentsWiring.IssuerNotSentMessage)
            .Validate(wiring => !wiring.ConsentGrantedToAnyUrl, ClientIdMetadataDocumentsWiring.ConsentGrantedToAnyUrlMessage)
            .Validate(wiring => wiring.PrivateNetworksBlocked, ClientIdMetadataDocumentsWiring.PrivateNetworksReachedMessage)
            .ValidateOnStart();

        return builder;
    }

    /// <summary>
    /// Whether the consent provider the container resolves grants every client everything it asks for.
    /// </summary>
    /// <remarks>
    /// Read from the registration the container resolves, the last one, by the type it registers, so neither the order
    /// of the host's calls nor building the provider at startup decides it. A host's own provider, or one it builds by
    /// an untyped factory, is not that one.
    /// </remarks>
    private static bool GrantsConsentToEveryClient(IServiceCollection services)
        => services.LastOrDefault(descriptor =>
                   descriptor is { IsKeyedService: false } &&
                   descriptor.ServiceType == typeof(IUserConsentsProvider))?
               .ResolveImplementationType() is { } implementation &&
           typeof(NullConsentService).IsAssignableFrom(implementation);
}
