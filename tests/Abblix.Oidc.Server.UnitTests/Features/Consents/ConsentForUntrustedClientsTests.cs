// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Threading.Tasks;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.ClientIdMetadataDocuments;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Consents;

/// <summary>
/// A host granting every client everything it asks for does not start while an untrusted client may get in: a metadata
/// document accepted from any URL, or a dynamic registration asking no initial access token. Any such client could
/// obtain an end user's tokens without the end user being asked (RFC 9700 section 4.11.2).
/// </summary>
public class ConsentForUntrustedClientsTests
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

        /// <summary>The provider granting everything, decorated by the host, so the host's decorator answers first.</summary>
        GrantedDecorated,
    }

    /// <summary>
    /// The way an untrusted client gets in.
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
    [InlineData(Way.MetadataDocument, Consent.GrantedDecorated, true, true)]
    [InlineData(Way.DynamicRegistration, Consent.GrantedBefore, true, false)]
    [InlineData(Way.DynamicRegistration, Consent.GrantedAfter, true, false)]
    [InlineData(Way.DynamicRegistration, Consent.GrantedBefore, false, true)]
    [InlineData(Way.DynamicRegistration, Consent.HostsAfterGranted, true, true)]
    [InlineData(Way.DynamicRegistration, Consent.HostsBeforeGranted, true, true)]
    [InlineData(Way.DynamicRegistration, Consent.None, true, true)]
    [InlineData(Way.DynamicRegistration, Consent.GrantedDecorated, true, true)]
    public async Task AHostGrantingEveryClientEverything_StartsOnlyWhenNoUntrustedClientGetsIn(
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
                options.ClientIdMetadataDocuments = options.ClientIdMetadataDocuments with { AllowedClientIdPrefixes = ["https://apps.example.com/"] };

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

            case Consent.GrantedDecorated:
                services.AddConsentGrantedForEveryClient();
                Register(services, way);
                services.Decorate<IUserConsentsProvider, HostsDecorator>();
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

    /// <summary>
    /// Registration requiring a software statement from an issuer the host trusts is closed, though it asks no initial
    /// access token, so a host granting every client everything starts with it.
    /// </summary>
    [Fact]
    public async Task RegistrationRequiringATrustedSoftwareStatement_IsNoOpenRegistration()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddSingleton(Mock.Of<IClientInfoProvider>());
        services.Configure<OidcOptions>(options =>
        {
            options.RequireInitialAccessToken = false;
            options.SoftwareStatement.RequireSoftwareStatement = true;
            options.SoftwareStatement.TrustedIssuers =
            [
                new TrustedIssuer
                {
                    Issuer = "https://statements.example.com",
                    JwksUri = new Uri("https://statements.example.com/jwks"),
                },
            ];
        });
        services.AddConsentGrantedForEveryClient();
        Register(services, Way.DynamicRegistration);

        await using var provider = services.BuildServiceProvider();
        await provider.GetRequiredService<IAsyncStartupValidator>().ValidateAsync(TestContext.Current.CancellationToken);
    }

    private static string MessageOf(Way way) => way switch
    {
        Way.MetadataDocument => ConsentForUntrustedClients.AnyUrlMessage,
        Way.DynamicRegistration => ConsentForUntrustedClients.AnyRegistrantMessage,
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

    /// <summary>
    /// A host's decorator over the consent provider, which the check takes for the host's own provider.
    /// </summary>
    private sealed class HostsDecorator(IUserConsentsProvider inner) : IUserConsentsProvider
    {
        public Task<UserConsents> GetUserConsentsAsync(
            TenantDefinition tenant, ValidAuthorizationRequest request, AuthSession authSession)
            => inner.GetUserConsentsAsync(tenant, request, authSession);
    }

    private sealed class Registered(IServiceCollection services) : IOidcServerBuilder
    {
        public IServiceCollection Services => services;
    }
}
