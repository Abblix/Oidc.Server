// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// The client a metadata document is fetched on is guarded against SSRF under the name it publishes, and that name
/// reaches it: draft-ietf-oauth-client-id-metadata-document section 10.7 has the server "MUST NOT fetch a Client ID
/// Metadata Document URL ... that resolve[s] to special-use IP addresses".
/// </summary>
public class ClientIdMetadataDocumentTransportTests
{
    private static ServiceCollection Registration()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddSingleton(Mock.Of<IClientInfoProvider>());
        new Registered(services).AddClientIdMetadataDocuments();
        return services;
    }

    [Fact]
    public void ThePublishedName_ReachesAClientWhoseHandlersTheHostsWrap_OverTheSsrfValidation()
    {
        var services = Registration();
        services.AddHttpClient(ClientIdMetadataDocumentTransport.HttpClientName)
            .AddHttpMessageHandler(() => new HostHandler());

        using var provider = services.BuildServiceProvider();
        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(ClientIdMetadataDocumentTransport.HttpClientName);
        var chain = Chain(handler).ToList();

        var host = chain.FindIndex(link => link is HostHandler);
        var guard = chain.FindIndex(link => link is SsrfValidatingHttpMessageHandler);
        Assert.True(host >= 0, "the host's handler is not on the client the documents are fetched with");
        Assert.True(guard > host, "the SSRF validation is not beneath the host's handler");
        var transport = Assert.IsType<HttpClientHandler>(((DelegatingHandler)chain[guard]).InnerHandler);
        Assert.False(transport.AllowAutoRedirect);
    }

    /// <summary>
    /// Wrapped twice, the store would fetch a document it cannot resolve once in each wrapper.
    /// </summary>
    [Fact]
    public async Task CallingItTwice_FetchesADocumentOncePerLookup()
    {
        const string clientId = "https://client.example.com/metadata.json";
        var origin = new MetadataDocumentOrigin();
        var services = Registration();
        new Registered(services).AddClientIdMetadataDocuments();
        services.AddMemoryCache();
        services.AddHttpClient(ClientIdMetadataDocumentTransport.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => origin);

        await using var provider = services.BuildServiceProvider();
        var tenant = new TenantDefinition { Id = "tenant", Issuer = new Uri("https://issuer.example.com/") };

        Assert.Null(await provider.GetRequiredService<IClientInfoProvider>().TryFindClientAsync(tenant, clientId));
        Assert.Equal(1, origin.RequestsTo(clientId));
    }

    private static IEnumerable<HttpMessageHandler> Chain(HttpMessageHandler handler)
    {
        for (var current = handler; current is not null;)
        {
            yield return current;
            current = current is DelegatingHandler delegating ? delegating.InnerHandler : null;
        }
    }

    private sealed class HostHandler : DelegatingHandler;

    private sealed class Registered(IServiceCollection services) : IOidcServerBuilder
    {
        public IServiceCollection Services => services;
    }
}
