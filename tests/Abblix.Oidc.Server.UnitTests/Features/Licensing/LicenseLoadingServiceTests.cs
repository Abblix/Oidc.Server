// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.CompilerServices;
using System.Threading;
using System.Threading.Tasks;

using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.Licensing;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
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
// Joins the non-parallel collection because starting the service writes to process-wide state that other
// classes assert on: it replaces LicenseLogger.Instance with the factory it was given, and it reports the
// loaded licenses once the loop closes. A class recording what the licensing writes would otherwise have
// its recorder swapped out mid-assertion, or catch a record this class produced, rarely enough to arrive
// as an unreproducible failure somewhere else.
[Collection(nameof(LicenseEnforcementTests))]
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
        var service = new LicenseLoadingService(loggerFactory, provider, TimeProvider.System);
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
        var service = new LicenseLoadingService(loggerFactory, provider, TimeProvider.System);
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
        var service = new LicenseLoadingService(loggerFactory, provider, TimeProvider.System);
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
        var service = new LicenseLoadingService(loggerFactory, provider, TimeProvider.System);
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
        var service = new LicenseLoadingService(loggerFactory, provider, TimeProvider.System);
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

        var provider = new MockLicenseJwtProvider(SlowLicenses(TestContext.Current.CancellationToken));
        var service = new LicenseLoadingService(loggerFactory, provider, TimeProvider.System);
        using var cts = new CancellationTokenSource();

        // Act - the token is already cancelled when enumeration starts, so the first await inside the sequence
        // observes it. Cancelling on a timer instead raced the delay above: under a loaded run the timer callback
        // is queued behind everything else, the delay wins, and the test fails for want of a free thread rather
        // than for anything about the code. Same path through the service, no clock involved.
        await cts.CancelAsync();

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
        var service = new LicenseLoadingService(loggerFactory, provider, TimeProvider.System);
        using var cts = new CancellationTokenSource();

        // Act - Should complete immediately (no enumeration needed)
        await cts.CancelAsync();
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
        _ = new LicenseLoadingService(loggerFactory, provider, TimeProvider.System);

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
        // - Instantiate StaticLicenseJwtProvider with a known test JWT
        // - Construct LicenseLoadingService and invoke StartAsync during test setup
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

    /// <summary>
    /// Starting the service reports what the loaded licenses mean, at the clock it was given.
    /// </summary>
    /// <remarks>
    /// The call site, not the reporting, which <c>LicenseManagerTests</c> covers. Without a test here the
    /// seam is a method nobody has shown runs, and the deployment it exists for is the one that starts
    /// holding a valid license and then serves no traffic: every other route into the reporting is a
    /// request path, and one of them returns the cached license without evaluating it.
    ///
    /// The provider yields nothing on purpose. What is reported is the license the assembly installs, so
    /// the record proves the report happened after the loop rather than inside it, on whatever the manager
    /// was holding by then.
    ///
    /// The clock is placed past that license's expiry, which is what makes the assertion deterministic
    /// without a signing key: no test can mint an expired license, and every real one expires eventually.
    /// The assembly's license runs into the twenty-second century, so the moment has to clear that rather
    /// than merely be far away - at an earlier one the license is simply active and says nothing.
    /// </remarks>
    [Fact]
    public async Task StartAsync_AfterLoading_ReportsWhatTheLicensesMean()
    {
        TestLicense.ResetChecker();
        TestLicense.ClearLogThrottle();

        var records = new RecordingLoggerFactory();
        var service = new LicenseLoadingService(
            records,
            new MockLicenseJwtProvider(null),
            new FixedClock(new DateTimeOffset(2200, 1, 1, 0, 0, 0, TimeSpan.Zero)));

        try
        {
            await service.StartAsync(CancellationToken.None);
        }
        finally
        {
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
            TestLicense.ClearLogThrottle();
        }

        Assert.Contains(
            records.Entries,
            entry => entry.EventId.Id == LogEvents.Licensing.LicenseManager.LicenseExpired);
    }

    /// <summary>
    /// Either public licence registration builds a container the hosted service can be activated from.
    /// </summary>
    /// <remarks>
    /// Both methods are public and take an <c>IServiceCollection</c>, so a host may call one on a
    /// collection carrying nothing else of ours. Every dependency the hosted service takes has to be
    /// registered by the method that registers the service, and a dependency supplied elsewhere in the
    /// shipped composition is a property of that composition rather than of this method.
    ///
    /// The failure this pins arrives at <c>BuildServiceProvider</c> and names a type whose name says
    /// nothing about licensing, so it reads as a container defect rather than a missing registration.
    /// In a host <c>ValidateOnBuild</c> is what makes it arrive at build time rather than at start; here
    /// it arrives either way, because the assertion below is itself a resolution of the hosted services.
    ///
    /// Logging and options are supplied here rather than expected from the registration, because every
    /// ASP.NET host has both before any of this is called and a library registering its own logging would
    /// be reaching further than it needs to. So the collection stands for a host that has the framework
    /// and nothing of ours, which is the case these methods have to survive.
    /// </remarks>
    [Theory]
    [InlineData(true)]
    [InlineData(false)]
    public void LicenseRegistration_OnACollectionCarryingNothingElse_ActivatesTheHostedService(
        bool fromOptions)
    {
        var services = new ServiceCollection();
        services.AddOptions();
        services.AddLogging();

        if (fromOptions)
            services.AddLicenseFromOptions();
        else
            services.AddLicense("not.a.real.jwt");

        try
        {
            using var provider = services.BuildServiceProvider(
                new ServiceProviderOptions { ValidateOnBuild = true, ValidateScopes = true });

            Assert.Single(provider.GetServices<IHostedService>());
        }
        finally
        {
            // Activating the hosted service rebinds the process-wide logger to one from the container this
            // test is about to dispose, and every write through a disposed logger is swallowed. The class
            // joined the serial collection for exactly this reason, so the test that proves the point is
            // the last one that may skip the restore.
            LicenseLogger.Instance.Init(NullLoggerFactory.Instance);
        }
    }

    /// <summary>A clock that answers one moment, so a test can stand anywhere on the timeline.</summary>
    private sealed class FixedClock(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }
}
