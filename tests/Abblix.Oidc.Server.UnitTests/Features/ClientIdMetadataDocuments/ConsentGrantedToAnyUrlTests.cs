// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ClientIdMetadataDocuments;

/// <summary>
/// A host granting every client everything it asks for does not start while it accepts a metadata document from any
/// URL: any URL could then name itself a client and obtain an end user's tokens without the end user being asked.
/// </summary>
public class ConsentGrantedToAnyUrlTests
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

    [Theory]
    [InlineData(Consent.GrantedBefore, false, false)]
    [InlineData(Consent.GrantedAfter, false, false)]
    [InlineData(Consent.GrantedBefore, true, true)]
    [InlineData(Consent.GrantedAfter, true, true)]
    [InlineData(Consent.HostsAfterGranted, false, true)]
    [InlineData(Consent.HostsBeforeGranted, false, true)]
    [InlineData(Consent.None, false, true)]
    public void AHostGrantingEveryClientEverything_StartsOnlyWithAnAllowList(
        Consent consent,
        bool allowList,
        bool starts)
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddSingleton(Mock.Of<IClientInfoProvider>());
        if (allowList)
        {
            services.Configure<OidcOptions>(options =>
                options.ClientIdMetadataDocuments.AllowedClientIdPrefixes = ["https://apps.example.com/"]);
        }

        switch (consent)
        {
            case Consent.None:
                Register(services);
                break;

            case Consent.GrantedBefore:
                services.AddConsentGrantedForEveryClient();
                Register(services);
                break;

            case Consent.GrantedAfter:
                Register(services);
                services.AddConsentGrantedForEveryClient();
                break;

            case Consent.HostsAfterGranted:
                services.AddConsentGrantedForEveryClient();
                Register(services);
                services.AddSingleton(Mock.Of<IUserConsentsProvider>());
                break;

            case Consent.HostsBeforeGranted:
                services.AddSingleton(Mock.Of<IUserConsentsProvider>());
                services.AddConsentGrantedForEveryClient();
                Register(services);
                break;

            default:
                throw new ArgumentOutOfRangeException(nameof(consent), consent, null);
        }

        using var provider = services.BuildServiceProvider();
        var check = () => provider.GetRequiredService<IOptions<ClientIdMetadataDocumentsWiring>>().Value;

        if (starts)
        {
            Assert.NotNull(check());
        }
        else
        {
            var refusal = Assert.Throws<OptionsValidationException>(check);
            Assert.Equal([ClientIdMetadataDocumentsWiring.ConsentGrantedToAnyUrlMessage], refusal.Failures);
        }
    }

    private static void Register(IServiceCollection services) => new Registered(services).AddClientIdMetadataDocuments();

    private sealed class Registered(IServiceCollection services) : IOidcServerBuilder
    {
        public IServiceCollection Services => services;
    }
}
