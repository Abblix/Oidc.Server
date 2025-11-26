// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.

using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.DependencyInjection.UnitTests;

/// <summary>
/// Tests for DecorateKeyed behavior with AddHttpClient-registered services.
/// Reproduces the issue where AddHttpClient registers a service but DecorateKeyed cannot find it.
/// </summary>
public class DecorateKeyedWithHttpClientTests
{
    public interface ITestFetcher
    {
        string Fetch(string url);
    }

    public class TestFetcher : ITestFetcher
    {
        public string Fetch(string url) => $"Fetched: {url}";
    }

    public class CachingTestFetcherDecorator : ITestFetcher
    {
        private readonly ITestFetcher _inner;

        public CachingTestFetcherDecorator(ITestFetcher inner)
        {
            _inner = inner;
        }

        public string Fetch(string url)
        {
            var result = _inner.Fetch(url);
            return $"Cached({result})";
        }
    }

    [Fact]
    public void DecorateKeyed_WithTransientService_ShouldFindUnkeyedService()
    {
        // Arrange
        var services = new ServiceCollection();

        // Register service as Transient (AddHttpClient registers as Transient)
        services.AddTransient<ITestFetcher, TestFetcher>();

        // Act - Try to decorate with a keyed decorator (similar to AddAuthorizationGrants)
        var exception = Record.Exception(() =>
        {
            services.DecorateKeyed<ITestFetcher, CachingTestFetcherDecorator>("TestKey");
        });

        // Assert
        Assert.Null(exception); // Should not throw

        // Verify the service can be resolved
        var serviceProvider = services.BuildServiceProvider();
        var keyedService = serviceProvider.GetRequiredKeyedService<ITestFetcher>("TestKey");
        Assert.NotNull(keyedService);
        Assert.IsType<CachingTestFetcherDecorator>(keyedService);
    }

    [Fact]
    public void DecorateKeyed_WithTransientService_ShouldCreateWorkingDecorator()
    {
        // Arrange
        var services = new ServiceCollection();

        // Register service as Transient
        services.AddTransient<ITestFetcher, TestFetcher>();

        // Decorate with keyed decorator
        services.DecorateKeyed<ITestFetcher, CachingTestFetcherDecorator>("TestKey");

        // Act
        var serviceProvider = services.BuildServiceProvider();
        var keyedService = serviceProvider.GetRequiredKeyedService<ITestFetcher>("TestKey");
        var result = keyedService.Fetch("http://example.com");

        // Assert
        Assert.Equal("Cached(Fetched: http://example.com)", result);
    }

    [Fact]
    public void DecorateKeyed_WithoutBaseService_ShouldThrowMeaningfulException()
    {
        // Arrange
        var services = new ServiceCollection();

        // Act
        var exception = Assert.Throws<System.InvalidOperationException>(() =>
        {
            services.DecorateKeyed<ITestFetcher, CachingTestFetcherDecorator>("TestKey");
        });

        // Assert
        Assert.Contains("No service of type", exception.Message);
        Assert.Contains("ITestFetcher", exception.Message);
        Assert.Contains("TestKey", exception.Message);
    }
}
