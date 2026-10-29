// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Reflection;
using Abblix.Jwt;
using Abblix.Oidc.Server.AspNetCore.MultiTenancy;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Endpoints.DeviceAuthorization;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.MinimalApi;
using Abblix.Oidc.Server.SharedSignals;
using Abblix.SecurityEvents.BackChannelLogout;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.MinimalApi;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http.Metadata;
using Microsoft.AspNetCore.Routing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

/// <summary>
/// Every parameter of a library route that the host's container provides is declared a service, so a host that has
/// not registered it is told which service is missing, and a check of the host's endpoints finds it.
/// </summary>
/// <remarks>
/// Minimal API decides when a route is built whether an undeclared parameter is a service, by asking the container
/// at that moment; one the host has not registered yet is read from a JSON body instead.
/// </remarks>
public sealed class LibraryRouteServiceParameterTests
{
    private const string Host = "https://auth.example.com";
    private const string Peer = "https://peer.example.com";

    private static readonly Assembly[] LibraryRouteAssemblies =
    [
        typeof(Abblix.Oidc.Server.MinimalApi.EndpointRouteBuilderExtensions).Assembly,
        typeof(SharedSignalsEndpointRouteBuilderExtensions).Assembly,
        typeof(BackChannelLogoutEndpointRouteBuilderExtensions).Assembly,
    ];

    [Fact]
    public async Task EveryServiceParameterOfALibraryRoute_IsDeclaredAService()
    {
        await TestLicense.Loaded;
        await using var app = BuildWithEveryRoute();
        var registrations = app.Services.GetRequiredService<IServiceProviderIsService>();

        var handlers = ((IEndpointRouteBuilder)app).DataSources
            .SelectMany(source => source.Endpoints)
            .Select(endpoint => endpoint.Metadata.GetMetadata<MethodInfo>())
            .OfType<MethodInfo>()
            .Where(method => LibraryRouteAssemblies.Contains(method.DeclaringType?.Assembly))
            .ToArray();
        Assert.NotEmpty(handlers);

        var undeclared = handlers
            .SelectMany(method => method.GetParameters())
            .Where(parameter => registrations.IsService(parameter.ParameterType) &&
                                !parameter.GetCustomAttributes().OfType<IFromServiceMetadata>().Any())
            .Select(parameter => $"{parameter.Member.DeclaringType}.{parameter.Member.Name}({parameter.Name})")
            .ToArray();

        // Joined, so a failure names every parameter rather than the first few
        Assert.True(undeclared.Length == 0, string.Join(Environment.NewLine, undeclared));
    }

    private static WebApplication BuildWithEveryRoute()
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Services.AddDistributedMemoryCache();
        builder.Services.AddMemoryCache();
        builder.Services.AddConsentGrantedForEveryClient();
        builder.Services
            .AddCheckSession()
            .AddRevocation()
            .AddIntrospection()
            .AddDynamicClientRegistration()
            .AddBackChannelAuthentication()
            .AddDeviceAuthorization();
        var server = builder.Services.AddOidcServices(options =>
        {
            options.EnabledEndpoints = OidcEndpoints.All;
            options.DeviceAuthorization = new DeviceAuthorizationOptions
            {
                VerificationUri = new Uri(Host + "/device"),
                CodeLifetime = TimeSpan.FromMinutes(15),
                PollingInterval = TimeSpan.FromSeconds(5),
                DeviceCodeLength = 32,
                UserCodeLength = 8,
            };
            options.Tenants.Add(new TenantDefinition
            {
                Id = "acme",
                Issuer = new Uri(Host + "/tenants/acme"),
                SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)],
            });
        });
        builder.Services.AddSecurityEvents();
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = Host,
            JwksUri = new Uri(Host + "/.well-known/jwks"),
        });
        server.AddSharedSignals();
        builder.Services.AddSharedSignalsReceiver(new SharedSignalsValidationOptions
        {
            ExpectedAudience = Host,
            ExpectedIssuers = [Peer],
            StreamIssuer = Peer,
        });
        builder.Services.AddBackChannelLogoutReceiver(new BackChannelLogoutValidationOptions
        {
            ExpectedAudience = Host,
            ExpectedIssuers = [Peer],
        });

        var app = builder.Build();
        app.UseMultiTenancy();
        app.MapOidcEndpoints();
        app.MapSharedSignalsTransmitterEndpoints();
        app.MapBackChannelLogoutEndpoint("/backchannel-logout");
        app.MapPushDeliveryEndpoint("/push");
        return app;
    }
}
