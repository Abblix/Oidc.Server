// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
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

    private static string[] Refusals(IServiceCollection services)
    {
        using var provider = services.BuildServiceProvider();
        try
        {
            _ = provider.GetRequiredService<IOptions<ClientIdMetadataDocumentsWiring>>().Value;
            return [];
        }
        catch (OptionsValidationException refusal)
        {
            return [.. refusal.Failures];
        }
    }

    [Fact]
    public void AHostWiredAsTheFeatureNeeds_Starts()
    {
        var services = Hosting();
        Register(services);

        Assert.Empty(Refusals(services));
    }

    /// <summary>
    /// A client store registered after the feature replaces the one resolving documents, while discovery would still
    /// advertise them.
    /// </summary>
    [Fact]
    public void AClientStoreRegisteredAfterTheFeature_IsRefused()
    {
        var services = Hosting();
        Register(services);
        services.AddSingleton(Mock.Of<IClientInfoProvider>());

        Assert.Equal([ClientIdMetadataDocumentsWiring.StoreReplacedMessage], Refusals(services));
    }

    /// <summary>
    /// Draft section 7: "The authorization response MUST include the iss parameter, as defined in [RFC9207]".
    /// </summary>
    [Fact]
    public void AuthorizationResponsesWithoutTheIssuer_AreRefused()
    {
        var services = Hosting();
        Register(services);
        services.AddScoped(_ => Mock.Of<IAuthorizationMetadataProvider>(
            metadata => !metadata.AuthorizationResponseIssParameterSupported));

        Assert.Equal([ClientIdMetadataDocumentsWiring.IssuerNotSentMessage], Refusals(services));
    }

    /// <summary>
    /// Draft section 10.7: the server "MUST NOT fetch a Client ID Metadata Document URL or any URLs contained within a
    /// Client ID Metadata Document that resolve to special-use IP addresses", so a host that stands that protection
    /// down does not start with documents on.
    /// </summary>
    [Fact]
    public void AHostReachingPrivateNetworks_IsRefused()
    {
        var services = Hosting();
        services.Configure<SecureHttpFetchOptions>(options => options.BlockPrivateNetworks = false);
        Register(services);

        Assert.Equal([ClientIdMetadataDocumentsWiring.PrivateNetworksReachedMessage], Refusals(services));
    }

    private static void Register(IServiceCollection services) => new Registered(services).AddClientIdMetadataDocuments();

    private sealed class Registered(IServiceCollection services) : IOidcServerBuilder
    {
        public IServiceCollection Services => services;
    }
}
