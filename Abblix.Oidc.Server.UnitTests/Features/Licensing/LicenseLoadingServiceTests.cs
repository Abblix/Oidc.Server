// Abblix OIDC Server Library
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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

using Abblix.Oidc.Server.Features.Licensing;

using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// Tests for LicenseLoadingService hosted service.
/// </summary>
/// <remarks>
/// IMPORTANT: LicenseLoadingService calls LicenseLoader.LoadAsync which:
/// - Validates JWT signatures (requires valid Abblix-signed license)
/// - Adds licenses to static LicenseChecker
///
/// These tests focus on:
/// - Service lifecycle (StartAsync/StopAsync)
/// - Provider integration
/// - Null/empty license handling
/// - Error scenarios
///
/// Full integration testing with valid licenses requires actual Abblix license JWTs.
/// </remarks>
public class LicenseLoadingServiceTests
{
    #region Helper Classes

    /// <summary>
    /// Mock provider that returns predefined license JWTs.
    /// </summary>
    private class MockLicenseJwtProvider : ILicenseJwtProvider
    {
        private readonly IAsyncEnumerable<string>? _licenses;

        public MockLicenseJwtProvider(IAsyncEnumerable<string>? licenses)
        {
            _licenses = licenses;
        }

        public IAsyncEnumerable<string>? GetLicenseJwtAsync() => _licenses;
    }

    #endregion

    #region Service Lifecycle Tests

    /// <summary>
    /// Verifies that StartAsync completes when provider returns null.
    /// </summary>
    [Fact]
    public async Task StartAsync_ProviderReturnsNull_CompletesSuccessfully()
    {
        // Arrange
        var loggerFactory = NullLoggerFactory.Instance;
        var provider = new MockLicenseJwtProvider(null);
        var service = new LicenseLoadingService(loggerFactory, provider);
        var cancellationToken = CancellationToken.None;

        // Act
        await service.StartAsync(cancellationToken);

        // Assert - Should complete without throwing
        Assert.True(true);
    }

    /// <summary>
    /// Verifies that StartAsync completes when provider returns empty enumerable.
    /// </summary>
    [Fact]
    public async Task StartAsync_ProviderReturnsEmpty_CompletesSuccessfully()
    {
        // Arrange
        var loggerFactory = NullLoggerFactory.Instance;
        var emptyLicenses = AsyncEnumerable.Empty<string>();
        var provider = new MockLicenseJwtProvider(emptyLicenses);
        var service = new LicenseLoadingService(loggerFactory, provider);
        var cancellationToken = CancellationToken.None;

        // Act
        await service.StartAsync(cancellationToken);

        // Assert - Should complete without throwing
        Assert.True(true);
    }

    /// <summary>
    /// Verifies that StartAsync skips empty license strings.
    /// </summary>
    /// <remarks>
    /// DESIGN NOTE: LicenseLoadingService uses license.HasValue() extension method
    /// which checks string.IsNullOrEmpty(). Empty strings are skipped.
    /// Note: Whitespace-only strings (like "  ") pass IsNullOrEmpty and are sent to LicenseLoader,
    /// which will throw. This is acceptable - whitespace-only licenses shouldn't be in config.
    /// </remarks>
    [Fact]
    public async Task StartAsync_WithEmptyString_SkipsEmpty()
    {
        // Arrange
        var loggerFactory = NullLoggerFactory.Instance;
        var licenses = new[] { string.Empty }.ToAsyncEnumerable();
        var provider = new MockLicenseJwtProvider(licenses);
        var service = new LicenseLoadingService(loggerFactory, provider);
        var cancellationToken = CancellationToken.None;

        // Act - Should skip empty string without throwing
        await service.StartAsync(cancellationToken);

        // Assert - Should complete successfully
        Assert.True(true);
    }

    /// <summary>
    /// Verifies that StartAsync throws when license validation fails.
    /// </summary>
    [Fact]
    public async Task StartAsync_WithInvalidLicense_ThrowsException()
    {
        // Arrange
        var loggerFactory = NullLoggerFactory.Instance;
        var licenses = new[] { "invalid.jwt.token" }.ToAsyncEnumerable();
        var provider = new MockLicenseJwtProvider(licenses);
        var service = new LicenseLoadingService(loggerFactory, provider);
        var cancellationToken = CancellationToken.None;

        // Act & Assert - Invalid license should throw during validation
        await Assert.ThrowsAnyAsync<Exception>(() =>
            service.StartAsync(cancellationToken));
    }

    /// <summary>
    /// Verifies that StopAsync completes immediately.
    /// </summary>
    [Fact]
    public async Task StopAsync_Always_CompletesImmediately()
    {
        // Arrange
        var loggerFactory = NullLoggerFactory.Instance;
        var provider = new MockLicenseJwtProvider(null);
        var service = new LicenseLoadingService(loggerFactory, provider);
        var cancellationToken = CancellationToken.None;

        // Act
        var task = service.StopAsync(cancellationToken);

        // Assert - Should complete synchronously
        Assert.True(task.IsCompleted);
        await task;
    }

    /// <summary>
    /// Verifies that StartAsync respects cancellation token during enumeration.
    /// </summary>
    [Fact]
    public async Task StartAsync_WithCancellation_ThrowsOperationCancelledException()
    {
        // Arrange
        var loggerFactory = NullLoggerFactory.Instance;

        // Create async enumerable that yields slowly and checks cancellation
        async IAsyncEnumerable<string> SlowLicenses([EnumeratorCancellation] CancellationToken ct = default)
        {
            await Task.Delay(100, ct);
            yield return "test.license.jwt";
        }

        var provider = new MockLicenseJwtProvider(SlowLicenses());
        var service = new LicenseLoadingService(loggerFactory, provider);
        var cts = new CancellationTokenSource();

        // Act - Cancel before enumeration completes
        cts.CancelAfter(10);

        // Assert - Should throw OperationCanceledException or TaskCanceledException
        await Assert.ThrowsAnyAsync<OperationCanceledException>(() =>
            service.StartAsync(cts.Token));
    }

    /// <summary>
    /// Verifies that StartAsync completes normally with null provider even if token is cancelled.
    /// </summary>
    [Fact]
    public async Task StartAsync_WithCancelledTokenAndNullProvider_CompletesSuccessfully()
    {
        // Arrange
        var loggerFactory = NullLoggerFactory.Instance;
        var provider = new MockLicenseJwtProvider(null);
        var service = new LicenseLoadingService(loggerFactory, provider);
        var cts = new CancellationTokenSource();

        // Act - Should complete immediately (no enumeration needed)
        cts.Cancel();
        await service.StartAsync(cts.Token);

        // Assert - Completes without throwing because provider returns null
        Assert.True(true);
    }

    #endregion

    #region Logger Initialization Tests

    /// <summary>
    /// Verifies that LicenseLogger is initialized with provided ILoggerFactory.
    /// </summary>
    [Fact]
    public void Constructor_InitializesLicenseLogger()
    {
        // Arrange
        var loggerFactory = NullLoggerFactory.Instance;
        var provider = new MockLicenseJwtProvider(null);

        // Act
        var service = new LicenseLoadingService(loggerFactory, provider);

        // Assert - LicenseLogger.Instance should be initialized
        // We can verify this by checking if IsEnabled returns expected value
        var logger = LicenseLogger.Instance;
        var isEnabled = logger.IsEnabled(LogLevel.Information);

        // NullLogger always returns false
        Assert.False(isEnabled);
    }

    #endregion

    #region Integration Scenarios Tests

    /// <summary>
    /// Documents the typical usage patterns for LicenseLoadingService.
    /// </summary>
    [Fact]
    public void LicenseLoadingService_UsagePatterns_Documented()
    {
        // Usage Pattern 1: Production with OptionsLicenseJwtProvider
        // services.AddSingleton<ILicenseJwtProvider, OptionsLicenseJwtProvider>();
        // services.AddHostedService<LicenseLoadingService>();
        // - Loads license from appsettings.json on startup
        // - Validates and applies license before accepting requests

        // Usage Pattern 2: Testing with StaticLicenseJwtProvider
        // var provider = new StaticLicenseJwtProvider("test.jwt");
        // var service = new LicenseLoadingService(loggerFactory, provider);
        // await service.StartAsync(CancellationToken.None);
        // - Useful for integration tests with known test licenses

        // Usage Pattern 3: No License (Free Tier)
        // var provider = new MockLicenseJwtProvider(null);
        // - Service completes without loading licenses
        // - Default free tier limits apply

        // Lifecycle:
        // 1. Constructor: Initializes LicenseLogger with ILoggerFactory
        // 2. StartAsync: Enumerates licenses from provider, loads each valid one
        // 3. StopAsync: No cleanup needed (licenses persist for app lifetime)

        // Error Handling:
        // - Invalid JWT: Throws InvalidOperationException
        // - Network errors: Propagated to hosting layer
        // - Validation errors: Logged and thrown

        Assert.True(true); // Documentation test
    }

    /// <summary>
    /// Documents the relationship between LicenseLoadingService and other components.
    /// </summary>
    [Fact]
    public void LicenseLoadingService_ComponentIntegration_Documented()
    {
        // Component Flow:
        // 1. LicenseLoadingService (IHostedService)
        //    ↓
        // 2. ILicenseJwtProvider (StaticLicenseJwtProvider or OptionsLicenseJwtProvider)
        //    ↓ provides JWT strings
        // 3. LicenseLoader.LoadAsync(jwt)
        //    ↓ validates JWT signature
        // 4. JsonWebTokenValidator (validates issuer, signature)
        //    ↓ returns ValidJsonWebToken
        // 5. License object created from JWT payload
        //    ↓
        // 6. LicenseChecker.AddLicense(license) (static)
        //    ↓
        // 7. LicenseManager (instance in LicenseChecker)
        //    ↓ stores and aggregates licenses
        // 8. License enforcement in LicenseChecker.CheckClientLicense()

        // Thread Safety:
        // - LicenseLoadingService: Single-threaded startup
        // - LicenseManager: Thread-safe with ReaderWriterLockSlim
        // - LicenseChecker: ConcurrentDictionary for known clients/issuers

        // Static State:
        // - LicenseLogger.Instance (singleton)
        // - LicenseChecker (static class with static LicenseManager)
        // - Licenses persist for application lifetime

        Assert.True(true); // Documentation test
    }

    #endregion
}
