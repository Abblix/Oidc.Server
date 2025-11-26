// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Abblix.Oidc.Server.Endpoints;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.JwtBearer;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.JwtBearer;

/// <summary>
/// Integration test that reproduces the exact scenario from Oidc.Server:
/// AddSecureHttpFetch() followed by AddJwtBearerServices() and JwtBearerIssuerProvider resolution.
/// </summary>
public class AddSecureHttpFetchIntegrationTests
{
    [Fact]
    public void AddSecureHttpFetch_ThenAddJwtBearerServices_ShouldResolveJwtBearerIssuerProvider()
    {
        // Arrange
        var services = new ServiceCollection();

        // Add required dependencies
        services.AddMemoryCache();
        services.AddDistributedMemoryCache(); // Required by DistributedJwtReplayCache
        services.AddSingleton(System.TimeProvider.System); // Required by DistributedJwtReplayCache
        services.AddOptions();
        services.AddLogging();

        // Act - Reproduce exact scenario from ServiceCollectionExtensions
        services.AddSecureHttpFetch(); // Registers ISecureHttpFetcher as Transient
        services.AddJwtBearerGrant(); // Calls DecorateKeyed with "JwtBearerJwks" key

        // Build service provider
        var serviceProvider = services.BuildServiceProvider();

        // Assert - JwtBearerIssuerProvider should resolve successfully with keyed ISecureHttpFetcher
        var exception = Record.Exception(() =>
        {
            var provider = serviceProvider.GetRequiredService<IJwtBearerIssuerProvider>();
            Assert.NotNull(provider);
        });

        Assert.Null(exception);
    }

    [Fact]
    public void KeyedSecureHttpFetcher_ShouldBeCachingDecorator()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddMemoryCache();
        services.AddDistributedMemoryCache();
        services.AddSingleton(System.TimeProvider.System);
        services.AddOptions();
        services.AddLogging();

        // Act
        services.AddSecureHttpFetch();
        services.AddJwtBearerGrant();

        var serviceProvider = services.BuildServiceProvider();

        // Assert - Keyed service should be decorated with caching
        var keyedFetcher = serviceProvider.GetRequiredKeyedService<ISecureHttpFetcher>(
            JwtBearerIssuerProvider.SecureHttpFetcherKey);

        Assert.NotNull(keyedFetcher);
        Assert.IsType<CachingSecureHttpFetcherDecorator>(keyedFetcher);
    }

    [Fact]
    public void NonKeyedSecureHttpFetcher_ShouldBeBaseImplementation()
    {
        // Arrange
        var services = new ServiceCollection();
        services.AddMemoryCache();
        services.AddDistributedMemoryCache();
        services.AddSingleton(System.TimeProvider.System);
        services.AddOptions();
        services.AddLogging();

        // Act
        services.AddSecureHttpFetch();
        services.AddJwtBearerGrant();

        var serviceProvider = services.BuildServiceProvider();

        // Assert - Non-keyed service should be base SecureHttpFetcher
        var baseFetcher = serviceProvider.GetRequiredService<ISecureHttpFetcher>();

        Assert.NotNull(baseFetcher);
        Assert.IsType<SecureHttpFetcher>(baseFetcher);
    }
}
