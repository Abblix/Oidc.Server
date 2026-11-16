// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.BackChannelAuthentication.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.ImplicitFlow;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Oidc.Server.Features.UserInfo;
using Microsoft.AspNetCore.Builder;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.Conformance.TestHost;

/// <summary>
/// The server the OpenID Foundation conformance suite is pointed at, apart from its transport adapter: its listeners,
/// its tenant and clients, the features the plans exercise, and the pages the server leaves to its host.
/// </summary>
/// <remarks>
/// The host runs as a container on the suite's own Docker network, so the suite's browser and its back channel reach
/// it by one name, and it reaches the suite by the name the suite writes into every URL it hands out.
/// conformance/run.ps1 drives a run. The OpenID Connect plans register their clients with the suite as they go; the
/// FAPI and CIBA plans authenticate as static clients, which the host mints at startup with their keys and
/// certificates and writes the suite's configuration for (<see cref="FapiPlanFamily"/>).
/// </remarks>
public static class ConformanceHost
{
    /// <summary>
    /// Configures everything but the transport adapter, which registers the server through
    /// <paramref name="addOidcServices"/>.
    /// </summary>
    /// <param name="builder">The host's application builder.</param>
    /// <param name="addOidcServices">The adapter's <c>AddOidcServices</c>, called with the server's options.</param>
    /// <returns>The pages the host serves itself, mapped once the application is built.</returns>
    public static async Task<ConformancePages> ConfigureAsync(
        WebApplicationBuilder builder,
        Action<Action<OidcOptions>> addOidcServices)
    {
        var settings = builder.Configuration.GetSection("Conformance");
        var issuer = new Uri(Required(settings, "Issuer"));
        var suite = new Uri(Required(settings, "SuiteBaseUrl"));
        var mtlsBase = new Uri(Required(settings, "MtlsBaseUrl"));
        var userEmail = Required(settings, "UserEmail");
        // The password is in no settings file: the run script makes a fresh one for every run and hands it over
        // through the environment (Conformance__UserPassword)
        var user = new ConformanceUser(userEmail, Required(settings, "UserPassword"));

        builder.WebHost.ListenForSuite(issuer, mtlsBase);

        var services = builder.Services;
        services.AddSingleton(user);
        services.AddSingleton<IUserInfoProvider>(user);
        services.AddConsentGrantedForEveryClient();

        // The certified profiles include the Implicit and Hybrid ones, whose response types are off unless a host asks.
        // CIBA, a grant-bearing feature, comes before the server, which composes the grant handlers when it is added
        services.EnableImplicitFlow();
        services.AddDynamicClientRegistration();
        services.AddRevocation();
        services.AddIntrospection();
        services.AddCheckSession();
        services.AddFrontChannelLogout();
        services.AddBackChannelLogout();
        services.AddSingleton<IUserDeviceAuthenticationHandler, ConformanceUserDevice>();
        services.AddBackChannelAuthentication();

        var fapiFamilies = FapiPlanFamily.All
            .Select(family => family.Declare(issuer, mtlsBase, suite, userEmail))
            .ToArray();

        // The run script names a directory for the configurations of the plans run with static clients
        if (settings["PlanConfigurations"] is { Length: > 0 } planConfigurations)
        {
            await PlanConfigurationFiles.WriteAsync(
                planConfigurations, fapiFamilies.SelectMany(declared => declared.PlanConfigurations));
        }

        var tenant = ConformanceServer.DeclareTenant(
            issuer, mtlsBase, fapiFamilies.SelectMany(declared => declared.Clients));
        addOidcServices(options => ConformanceServer.Configure(options, tenant));

        services.Decorate<IClientInfoManager, PkceOptionalForRegisteredClients>();
        services.Decorate<IAuthServiceKeysProvider, RotatingSigningKeys>();
        services.Decorate<IUserConsentsProvider, RefusedAuthorizations>();

        // Every client the suite registers keeps its key set, request objects and logout endpoints on the suite's
        // host, which sits at a private address on this network: name that one destination instead of lifting the
        // refusal
        services.Configure<SecureHttpFetchOptions>(fetch => fetch.AllowedDestinations = [suite]);
        services.TrustSuiteCertificate(suite.Host);

        services.AddAuthentication().AddCookie();
        services.AddAuthorization();
        services.AddCors();
        services.AddMemoryCache();
        services.AddDistributedMemoryCache();
        services.AddHttpContextAccessor();

        return new ConformancePages(tenant);
    }

    private static string Required(IConfiguration section, string key)
        => section[key] ?? throw new InvalidOperationException($"Conformance:{key} is not set");
}
