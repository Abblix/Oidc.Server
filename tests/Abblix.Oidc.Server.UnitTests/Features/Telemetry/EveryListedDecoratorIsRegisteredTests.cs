// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Linq;
using System.Reflection;
using Abblix.Jwt;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Features.UserInfo;
using Abblix.Oidc.Server.Mvc;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Microsoft.Extensions.DependencyInjection;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// A server with every endpoint on applies the decorator of every service either list names, so a registration
/// dropped from an endpoint's setup leaves its decorator unapplied and this test red.
/// </summary>
public sealed class EveryListedDecoratorIsRegisteredTests
{
    [Fact]
    public void AServerWithEveryEndpoint_AppliesEveryListedDecorator()
    {
        var services = Server();
        var applied = services
            .Select(descriptor => descriptor.ImplementationInstance)
            .OfType<TelemetryDecoratorsRegistered>()
            .Single()
            .Decorators
            .Select(decorator => decorator.Name)
            .ToHashSet();

        var library = typeof(TelemetryDecoratorsRegistered).Assembly;
        var listed = library.GetCustomAttributes<ObservedEndpointAttribute>().Select(observed => observed.Service)
            .Concat(library.GetCustomAttributes<ObservedStageAttribute>().Select(observed => observed.Service))
            .Select(service => $"Observed{service.Name[1..]}")
            .ToArray();

        Assert.NotEmpty(listed);
        Assert.All(listed, decorator => Assert.Contains(decorator, applied));
    }

    /// <summary>
    /// An enricher the host registers per request is taken by the decorator of each request's handler, which lives as
    /// long, so validated scopes resolve it.
    /// </summary>
    [Fact]
    public void AnEnricherRegisteredPerRequest_ResolvesWithTheEndpointsHandler()
    {
        // Without the device endpoint, whose settings the options check asks for once anything is resolved
        var services = Server(withDeviceAuthorization: false);
        services.AddScoped(_ => Mock.Of<IEndpointSpanEnricher>());

        using var provider = services.BuildServiceProvider(new ServiceProviderOptions { ValidateScopes = true });
        using var scope = provider.CreateScope();

        Assert.IsType<ObservedTokenHandler>(scope.ServiceProvider.GetRequiredService<ITokenHandler>());
    }

    private static ServiceCollection Server(bool withDeviceAuthorization = true)
    {
        var services = new ServiceCollection();
        services.AddDistributedMemoryCache();
        services.AddMemoryCache();
        services.AddSingleton(Mock.Of<IUserCredentialsAuthenticator>());
        services.AddSingleton(Mock.Of<IUserInfoProvider>());
        services.AddBackChannelAuthentication();
        if (withDeviceAuthorization)
            services.AddDeviceAuthorization();
        services.AddDynamicClientRegistration();
        services.AddRevocation();
        services.AddIntrospection();
        services.AddCheckSession();
        services.AddOidcServices(options =>
        {
            options.Issuer = TestConstants.DefaultIssuer.OriginalString;
            options.SigningKeys = [JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)];
        });

        return services;
    }
}
