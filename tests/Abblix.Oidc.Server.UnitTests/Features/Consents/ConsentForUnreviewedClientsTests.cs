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
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Consents;

/// <summary>
/// A host granting every client everything it asks for does not start while somebody nobody reviewed may become a
/// client: a metadata document accepted from any URL, or a dynamic registration asking no initial access token. Any
/// such client could obtain an end user's tokens without the end user being asked (RFC 9700 section 4.11.2).
/// </summary>
public class ConsentForUnreviewedClientsTests
{
    public enum Consent
    {
        /// <summary>No consent provider at all, which another startup check judges.</summary>
        None,

        /// <summary>The provider granting everything, registered before the feature.</summary>
        GrantedBefore,

        /// <summary>The provider granting everything, registered after the feature.</summary>
        GrantedAfter,

        /// <summary>The host's own provider, registered after the call granting everything, so it wins.</summary>
        HostsAfterGranted,

        /// <summary>The host's own provider, registered first, so the call granting everything adds nothing.</summary>
        HostsBeforeGranted,
    }

    /// <summary>
    /// The way a client nobody reviewed gets in.
    /// </summary>
    public enum Way
    {
        MetadataDocument,
        DynamicRegistration,
    }

    [Theory]
    [InlineData(Way.MetadataDocument, Consent.GrantedBefore, true, false)]
    [InlineData(Way.MetadataDocument, Consent.GrantedAfter, true, false)]
    [InlineData(Way.MetadataDocument, Consent.GrantedBefore, false, true)]
    [InlineData(Way.MetadataDocument, Consent.GrantedAfter, false, true)]
    [InlineData(Way.MetadataDocument, Consent.HostsAfterGranted, true, true)]
    [InlineData(Way.MetadataDocument, Consent.HostsBeforeGranted, true, true)]
    [InlineData(Way.MetadataDocument, Consent.None, true, true)]
    [InlineData(Way.DynamicRegistration, Consent.GrantedBefore, true, false)]
    [InlineData(Way.DynamicRegistration, Consent.GrantedAfter, true, false)]
    [InlineData(Way.DynamicRegistration, Consent.GrantedBefore, false, true)]
    [InlineData(Way.DynamicRegistration, Consent.HostsAfterGranted, true, true)]
    [InlineData(Way.DynamicRegistration, Consent.HostsBeforeGranted, true, true)]
    [InlineData(Way.DynamicRegistration, Consent.None, true, true)]
    public async Task AHostGrantingEveryClientEverything_StartsOnlyWhenNobodyUnreviewedGetsIn(
        Way way,
        Consent consent,
        bool open,
        bool starts)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddSingleton(Mock.Of<IClientInfoProvider>());
        services.Configure<OidcOptions>(options =>
        {
            if (!open)
                options.ClientIdMetadataDocuments.AllowedClientIdPrefixes = ["https://apps.example.com/"];

            options.RequireInitialAccessToken = !open;
        });

        switch (consent)
        {
            case Consent.None:
                Register(services, way);
                break;

            case Consent.GrantedBefore:
                services.AddConsentGrantedForEveryClient();
                Register(services, way);
                break;

            case Consent.GrantedAfter:
                Register(services, way);
                services.AddConsentGrantedForEveryClient();
                break;

            case Consent.HostsAfterGranted:
                services.AddConsentGrantedForEveryClient();
                Register(services, way);
                services.AddSingleton(Mock.Of<IUserConsentsProvider>());
                break;

            case Consent.HostsBeforeGranted:
                services.AddSingleton(Mock.Of<IUserConsentsProvider>());
                services.AddConsentGrantedForEveryClient();
                Register(services, way);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(consent), consent, null);
        }

        // Read as the host starts, so a check that is not run at startup does not count
        await using var provider = services.BuildServiceProvider();
        var start = () => provider.GetRequiredService<IAsyncStartupValidator>().ValidateAsync(TestContext.Current.CancellationToken);

        if (starts)
        {
            await start();
        }
        else
        {
            var refusal = await Assert.ThrowsAsync<OptionsValidationException>(start);
            Assert.Equal([MessageOf(way)], refusal.Failures);
        }
    }

    private static string MessageOf(Way way) => way switch
    {
        Way.MetadataDocument => ConsentForUnreviewedClients.AnyUrlMessage,
        Way.DynamicRegistration => ConsentForUnreviewedClients.AnyRegistrantMessage,
        _ => throw new ArgumentOutOfRangeException(nameof(way), way, null),
    };

    private static void Register(IServiceCollection services, Way way)
    {
        switch (way)
        {
            case Way.MetadataDocument:
                new Registered(services).AddClientIdMetadataDocuments();
                break;

            case Way.DynamicRegistration:
                services.AddDynamicClientRegistration();
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(way), way, null);
        }
    }

    private sealed class Registered(IServiceCollection services) : IOidcServerBuilder
    {
        public IServiceCollection Services => services;
    }
}
