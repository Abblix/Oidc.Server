// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// What a host's registrations must hold for clients to be resolved from their documents, each refused at startup by
/// its own rule.
/// </summary>
public class ClientIdMetadataDocumentsWiringTests
{
    private static ServiceCollection Hosting()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddSingleton(Mock.Of<IClientInfoProvider>());
        return services;
    }

    /// <summary>
    /// What the host's startup refuses, read as the host starts rather than from the options, so a check that is not
    /// run at startup is not counted.
    /// </summary>
    private static async Task<string[]> Refusals(IServiceCollection services)
    {
        await using var provider = services.BuildServiceProvider();
        try
        {
            await provider.GetRequiredService<IAsyncStartupValidator>().ValidateAsync(TestContext.Current.CancellationToken);
            return [];
        }
        catch (OptionsValidationException refusal)
        {
            return [.. refusal.Failures];
        }
    }

    [Fact]
    public async Task AHostWiredAsTheFeatureNeeds_Starts()
    {
        var services = Hosting();
        Register(services);

        Assert.Empty(await Refusals(services));
    }

    /// <summary>
    /// A client store registered after the feature replaces the one resolving documents, while discovery would still
    /// advertise them.
    /// </summary>
    [Fact]
    public async Task AClientStoreRegisteredAfterTheFeature_IsRefused()
    {
        var services = Hosting();
        Register(services);
        services.AddSingleton(Mock.Of<IClientInfoProvider>());

        Assert.Equal([ClientIdMetadataDocumentsWiring.StoreReplacedMessage], await Refusals(services));
    }

    /// <summary>
    /// Draft section 7: "The authorization response MUST include the iss parameter, as defined in [RFC9207]".
    /// </summary>
    [Fact]
    public async Task AuthorizationResponsesWithoutTheIssuer_AreRefused()
    {
        var services = Hosting();
        Register(services);
        services.AddScoped(_ => Mock.Of<IAuthorizationMetadataProvider>(
            metadata => !metadata.AuthorizationResponseIssParameterSupported));

        Assert.Equal([ClientIdMetadataDocumentsWiring.IssuerNotSentMessage], await Refusals(services));
    }

    /// <summary>
    /// Draft section 10.7: the server "MUST NOT fetch a Client ID Metadata Document URL or any URLs contained within a
    /// Client ID Metadata Document that resolve to special-use IP addresses", so a host that stands that protection
    /// down does not start with documents on.
    /// </summary>
    [Fact]
    public async Task AHostReachingPrivateNetworks_IsRefused()
    {
        var services = Hosting();
        services.Configure<SecureHttpFetchOptions>(options => options.BlockPrivateNetworks = false);
        Register(services);

        Assert.Equal([ClientIdMetadataDocumentsWiring.PrivateNetworksReachedMessage], await Refusals(services));
    }

    /// <summary>
    /// Draft section 10.7: servers "MUST NOT apply this exception in production deployments", so a host in the
    /// Production environment does not start with loopback documents on; any other environment, and a host that
    /// registers none, starts.
    /// </summary>
    [Theory]
    [InlineData("Production", ClientIdMetadataDocumentAddresses.AllowLoopback, false)]
    [InlineData("Development", ClientIdMetadataDocumentAddresses.AllowLoopback, true)]
    [InlineData("Staging", ClientIdMetadataDocumentAddresses.AllowLoopback, true)]
    [InlineData("Production", ClientIdMetadataDocumentAddresses.PublicOnly, true)]
    [InlineData(null, ClientIdMetadataDocumentAddresses.AllowLoopback, true)]
    public async Task LoopbackDocuments_AreRefusedInProduction(
        string? environment,
        ClientIdMetadataDocumentAddresses addresses,
        bool starts)
    {
        var services = Hosting();
        if (environment is not null)
            services.AddSingleton(Mock.Of<IHostEnvironment>(host => host.EnvironmentName == environment));
        services.Configure<OidcOptions>(options => options.ClientIdMetadataDocuments.DocumentAddresses = addresses);
        Register(services);

        Assert.Equal(
            starts ? [] : [ClientIdMetadataDocumentsWiring.LoopbackInProductionMessage],
            await Refusals(services));
    }

    /// <summary>
    /// A proxy resolves the name on its own machine, so a loopback document would come from the proxy's loopback
    /// interface, not the one section 10.7 allows.
    /// </summary>
    [Theory]
    [InlineData(ClientIdMetadataDocumentAddresses.AllowLoopback, true, false)]
    [InlineData(ClientIdMetadataDocumentAddresses.AllowLoopback, false, true)]
    [InlineData(ClientIdMetadataDocumentAddresses.PublicOnly, true, true)]
    public async Task LoopbackDocuments_AreRefusedThroughAProxy(
        ClientIdMetadataDocumentAddresses addresses,
        bool proxied,
        bool starts)
    {
        var services = Hosting();
        if (proxied)
            services.Configure<SecureHttpFetchOptions>(options => options.OutboundProxy = new Uri("http://proxy.example.com:3128"));
        services.Configure<OidcOptions>(options => options.ClientIdMetadataDocuments.DocumentAddresses = addresses);
        Register(services);

        Assert.Equal(
            starts ? [] : [ClientIdMetadataDocumentsWiring.LoopbackThroughProxyMessage],
            await Refusals(services));
    }

    private static void Register(IServiceCollection services) => new Registered(services).AddClientIdMetadataDocuments();

    private sealed class Registered(IServiceCollection services) : IOidcServerBuilder
    {
        public IServiceCollection Services => services;
    }
}
