// Abblix OIDC Client Library
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

using Abblix.Oidc.Client;
using Abblix.Oidc.Client.Features.Authorization.Context;
using Abblix.Oidc.Client.Features.Authorization.Requests;
using Abblix.Oidc.Client.Features.Authorization.Responses;
using Abblix.Oidc.Client.Features.BackChannelLogout;
using Abblix.Oidc.Client.Features.ClientAuthentication;
using Abblix.Oidc.Client.Features.Discovery;
using Abblix.Oidc.Client.Features.EndSession;
using Abblix.Oidc.Client.Features.Revocation;
using Abblix.Oidc.Client.Features.SigningKeys;
using Abblix.Oidc.Client.Features.Tokens;
using Abblix.Oidc.Client.Features.UserInfo;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Client.E2E.Tests;

/// <summary>
/// A real Abblix OIDC Server, and an Abblix OIDC client wired to talk to it.
/// </summary>
/// <remarks>
/// The unit suites check each part of the client against stubs this repository writes, which cannot
/// disagree with what the client expects. This fixture puts a server that was never told about these tests
/// on the other end of every call, so a response shape the client assumed wrongly has somewhere to surface.
/// </remarks>
public sealed class ClientAgainstServerFixture : WebApplicationFactory<Program>, IAsyncLifetime
{
    /// <summary>
    /// The client identifier and secret the test host registers, and the address it registered for this
    /// client's callback.
    /// </summary>
    public const string ClientId = "e2e-confidential";

    public const string ClientSecret = "e2e-secret";

    public const string RedirectUri = "https://client.example.com/cb";

    /// <summary>
    /// The issuer the host declares. The client's authority has to be this exact value: its discovery
    /// refuses metadata whose declared issuer is not the authority it asked, and so it should.
    /// </summary>
    public const string Issuer = "https://auth.example.com";

    /// <summary>
    /// Extra registrations for the provider host, applied before it is built.
    /// </summary>
    /// <remarks>
    /// Set by a test that needs the provider configured differently - a client registered with a
    /// back-channel logout address, say - and only before the first access to the host, since that is when
    /// it is built.
    /// </remarks>
    public Action<IServiceCollection>? ConfigureProviderServices { get; set; }

    /// <inheritdoc />
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        if (ConfigureProviderServices is { } configure)
            builder.ConfigureTestServices(configure);
    }

    /// <summary>
    /// Builds the host once, before any test touches it, for the reason the server suite documents: the
    /// lazy build is not thread-safe and a second build mints a fresh signing key.
    /// </summary>
    public ValueTask InitializeAsync()
    {
        _ = Server;
        return ValueTask.CompletedTask;
    }

    /// <summary>
    /// A browser that reports where the provider redirected instead of chasing it to an address nothing is
    /// listening on. The callback belongs to the client, and reading it is the point.
    /// </summary>
    public HttpClient CreateBrowser()
        => CreateClient(new WebApplicationFactoryClientOptions { AllowAutoRedirect = false });

    /// <summary>
    /// Builds a container holding the client, with every outgoing call routed into the in-memory server.
    /// </summary>
    public ServiceProvider CreateOidcClient(
        Action<IServiceCollection>? configure = null, string? clientId = null)
    {
        var services = new ServiceCollection();

        AddClientServices(services, clientId);
        configure?.Invoke(services);

        return services.BuildServiceProvider();
    }

    /// <summary>
    /// Registers the client into someone else's container - an application host, for the tests that run one.
    /// </summary>
    public void AddClientServices(IServiceCollection services, string? clientId = null)
    {
        services
            .AddOidcClientCore(options => options.ClientId = clientId ?? ClientId)
            .AddDiscovery(options => options.Authority = new Uri(Issuer))
            .AddAuthorizationRequests(options =>
            {
                options.RedirectUri = new Uri(RedirectUri);
                // offline_access, so the provider issues a refresh token there is something to revoke.
                options.Scopes = ["openid", "profile", "offline_access"];
            })
            .AddAuthorizationResponseHandling()
            .AddClientAuthentication(options =>
            {
                options.Method = ClientAuthenticationMethods.ClientSecretPost;
                options.ClientSecret = ClientSecret;
            })
            .AddTokenRequests()
            .AddTokenRevocation()
            .AddUserInfo()
            .AddBackChannelLogout()

            // No post-logout address: RP-Initiated Logout 1.0 section 2 requires one to have been
            // registered with the provider beforehand, and this host registers none for this client. Asking
            // to be sent to an unregistered address is what a conformant provider refuses.
            .AddEndSessionRequests(_ => { })
            .AddOidcClientFacade();

        RouteIntoTheServer(services);
    }

    /// <summary>
    /// Sends every named client the library uses into the in-memory server instead of the network.
    /// </summary>
    /// <remarks>
    /// The addresses are left exactly as the provider published them - the handler dispatches on the path,
    /// so the client goes on believing it is talking to https://auth.example.com. Rewriting them to the
    /// test host would test a client configured differently from the one that ships.
    /// </remarks>
    private void RouteIntoTheServer(IServiceCollection services)
    {
        string[] clientNames =
        [
            DiscoveredMetadataProvider.HttpClientName,
            IssuerSigningKeysProvider.HttpClientName,
            TokenRequestService.HttpClientName,
            UserInfoService.HttpClientName,
            TokenRevocationService.HttpClientName,
        ];

        foreach (var name in clientNames)
        {
            services.AddHttpClient(name)
                .ConfigurePrimaryHttpMessageHandler(Server.CreateHandler);
        }
    }
}
