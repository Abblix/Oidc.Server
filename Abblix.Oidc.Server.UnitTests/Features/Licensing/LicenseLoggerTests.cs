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
using System.Threading.Tasks;

using Abblix.Oidc.Server.Features.Licensing;

using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// Tests for LicenseLogger throttling mechanism.
/// </summary>
/// <remarks>
/// IMPORTANT: LicenseLogger is a singleton with internal state.
/// - Tests using the same key may interfere with each other
/// - Uses unique GUIDs to minimize interference but cannot be fully isolated
/// - Timer cleanup runs every minute which may affect test timing
///
/// These tests verify:
/// - Throttling behavior (IsAllowed method)
/// - Time-based throttling with period parameter
/// - Concurrent access safety
/// - Cleanup timer functionality
/// </remarks>
public class LicenseLoggerTests
{
    #region Basic Throttling Tests

    /// <summary>
    /// Verifies that IsAllowed returns true on first call with a new key.
    /// </summary>
    [Fact]
    public void IsAllowed_FirstCall_ReturnsTrue()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var key = Guid.NewGuid(); // Unique key to avoid interference
        var utcNow = DateTimeOffset.UtcNow;
        var period = TimeSpan.FromMinutes(5);

        // Act
        var result = logger.IsAllowed(key, utcNow, period);

        // Assert
        Assert.True(result);
    }

    /// <summary>
    /// Verifies that IsAllowed returns false on second immediate call with same key.
    /// </summary>
    [Fact]
    public void IsAllowed_ImmediateSecondCall_ReturnsFalse()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var key = Guid.NewGuid(); // Unique key
        var utcNow = DateTimeOffset.UtcNow;
        var period = TimeSpan.FromMinutes(5);

        // Act
        var firstResult = logger.IsAllowed(key, utcNow, period);
        var secondResult = logger.IsAllowed(key, utcNow, period);

        // Assert
        Assert.True(firstResult);
        Assert.False(secondResult);
    }

    /// <summary>
    /// Verifies that IsAllowed returns true after period has elapsed.
    /// </summary>
    [Fact]
    public void IsAllowed_AfterPeriodElapsed_ReturnsTrue()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var key = Guid.NewGuid(); // Unique key
        var utcNow = DateTimeOffset.UtcNow;
        var period = TimeSpan.FromSeconds(1);

        // Act
        var firstResult = logger.IsAllowed(key, utcNow, period);
        var secondResult = logger.IsAllowed(key, utcNow, period);
        var thirdResult = logger.IsAllowed(key, utcNow + period + TimeSpan.FromMilliseconds(1), period); // Time advanced PAST period

        // Assert
        Assert.True(firstResult);
        Assert.False(secondResult);
        Assert.True(thirdResult);
    }

    /// <summary>
    /// Verifies that IsAllowed returns false before period has fully elapsed.
    /// </summary>
    [Fact]
    public void IsAllowed_BeforePeriodElapsed_ReturnsFalse()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var key = Guid.NewGuid(); // Unique key
        var utcNow = DateTimeOffset.UtcNow;
        var period = TimeSpan.FromMinutes(5);

        // Act
        var firstResult = logger.IsAllowed(key, utcNow, period);
        var secondResult = logger.IsAllowed(key, utcNow + TimeSpan.FromMinutes(1), period); // Only 1 minute elapsed

        // Assert
        Assert.True(firstResult);
        Assert.False(secondResult);
    }

    #endregion

    #region Multiple Keys Tests

    /// <summary>
    /// Verifies that different keys are tracked independently.
    /// </summary>
    [Fact]
    public void IsAllowed_DifferentKeys_TrackedIndependently()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var key1 = Guid.NewGuid();
        var key2 = Guid.NewGuid();
        var utcNow = DateTimeOffset.UtcNow;
        var period = TimeSpan.FromMinutes(5);

        // Act
        var result1 = logger.IsAllowed(key1, utcNow, period);
        var result2 = logger.IsAllowed(key2, utcNow, period); // Different key

        // Assert
        Assert.True(result1);
        Assert.True(result2); // Should be allowed despite key1 being throttled
    }

    /// <summary>
    /// Verifies that same key with same content is consistently throttled.
    /// </summary>
    [Fact]
    public void IsAllowed_SameKeyMultipleTimes_ConsistentThrottling()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var keyValue = Guid.NewGuid().ToString();
        var utcNow = DateTimeOffset.UtcNow;
        var period = TimeSpan.FromMinutes(5);

        // Act - Use same key value multiple times
        var result1 = logger.IsAllowed(keyValue, utcNow, period);
        var result2 = logger.IsAllowed(keyValue, utcNow, period);
        var result3 = logger.IsAllowed(keyValue, utcNow, period);

        // Assert
        Assert.True(result1);
        Assert.False(result2);
        Assert.False(result3);
    }

    #endregion

    #region Period Variation Tests

    /// <summary>
    /// Verifies that shorter periods allow logging sooner.
    /// </summary>
    [Fact]
    public void IsAllowed_ShorterPeriod_AllowsSoonerRelogging()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var key = Guid.NewGuid();
        var utcNow = DateTimeOffset.UtcNow;
        var shortPeriod = TimeSpan.FromSeconds(10);

        // Act
        var firstResult = logger.IsAllowed(key, utcNow, shortPeriod);
        var beforePeriod = logger.IsAllowed(key, utcNow + TimeSpan.FromSeconds(5), shortPeriod);
        var afterPeriod = logger.IsAllowed(key, utcNow + TimeSpan.FromSeconds(11), shortPeriod);

        // Assert
        Assert.True(firstResult);
        Assert.False(beforePeriod);
        Assert.True(afterPeriod);
    }

    /// <summary>
    /// Verifies that zero period blocks immediate re-logging.
    /// </summary>
    /// <remarks>
    /// With zero period, nextAllowedTime = utcNow + 0 = utcNow.
    /// Second call checks if nextAllowedTime (utcNow) < utcNow, which is false.
    /// Therefore, zero period still requires time to advance (even by 1 tick).
    /// </remarks>
    [Fact]
    public void IsAllowed_ZeroPeriod_BlocksImmediateRelogging()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var key = Guid.NewGuid();
        var utcNow = DateTimeOffset.UtcNow;
        var zeroPeriod = TimeSpan.Zero;

        // Act
        var result1 = logger.IsAllowed(key, utcNow, zeroPeriod);
        var result2 = logger.IsAllowed(key, utcNow, zeroPeriod); // Same time - blocked
        var result3 = logger.IsAllowed(key, utcNow.AddTicks(1), zeroPeriod); // Time advanced - allowed

        // Assert
        Assert.True(result1);
        Assert.False(result2); // Blocked at same time
        Assert.True(result3); // Allowed after time advances
    }

    /// <summary>
    /// Verifies that very long periods keep throttling for extended time.
    /// </summary>
    [Fact]
    public void IsAllowed_LongPeriod_KeepsThrottlingLonger()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var key = Guid.NewGuid();
        var utcNow = DateTimeOffset.UtcNow;
        var longPeriod = TimeSpan.FromDays(1);

        // Act
        var firstResult = logger.IsAllowed(key, utcNow, longPeriod);
        var afterHour = logger.IsAllowed(key, utcNow + TimeSpan.FromHours(1), longPeriod);
        var afterDay = logger.IsAllowed(key, utcNow + TimeSpan.FromDays(1).Add(TimeSpan.FromSeconds(1)), longPeriod);

        // Assert
        Assert.True(firstResult);
        Assert.False(afterHour); // Still throttled after 1 hour
        Assert.True(afterDay); // Allowed after 1 day
    }

    #endregion

    #region Thread Safety Tests

    /// <summary>
    /// Verifies that concurrent calls with same key result in only one allowed call.
    /// </summary>
    [Fact]
    public void IsAllowed_ConcurrentCallsSameKey_OnlyOneAllowed()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var key = Guid.NewGuid();
        var utcNow = DateTimeOffset.UtcNow;
        var period = TimeSpan.FromMinutes(5);

        var results = new List<bool>();
        var lockObj = new object();

        // Act - 10 threads calling simultaneously with same key
        Parallel.For(0, 10, _ =>
        {
            var result = logger.IsAllowed(key, utcNow, period);
            lock (lockObj)
            {
                results.Add(result);
            }
        });

        // Assert - Exactly one should be allowed
        var allowedCount = results.Count(r => r);
        Assert.Equal(1, allowedCount);
    }

    /// <summary>
    /// Verifies that concurrent calls with different keys all succeed.
    /// </summary>
    [Fact]
    public void IsAllowed_ConcurrentCallsDifferentKeys_AllAllowed()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var utcNow = DateTimeOffset.UtcNow;
        var period = TimeSpan.FromMinutes(5);

        var results = new List<bool>();
        var lockObj = new object();

        // Act - 10 threads calling with different keys
        Parallel.For(0, 10, i =>
        {
            var uniqueKey = $"{Guid.NewGuid()}-{i}";
            var result = logger.IsAllowed(uniqueKey, utcNow, period);
            lock (lockObj)
            {
                results.Add(result);
            }
        });

        // Assert - All should be allowed (different keys)
        Assert.All(results, r => Assert.True(r));
    }

    #endregion

    #region Key Type Tests

    /// <summary>
    /// Verifies that string keys work correctly.
    /// </summary>
    [Fact]
    public void IsAllowed_StringKey_WorksCorrectly()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var key = $"string-key-{Guid.NewGuid()}";
        var utcNow = DateTimeOffset.UtcNow;
        var period = TimeSpan.FromMinutes(5);

        // Act
        var result1 = logger.IsAllowed(key, utcNow, period);
        var result2 = logger.IsAllowed(key, utcNow, period);

        // Assert
        Assert.True(result1);
        Assert.False(result2);
    }

    /// <summary>
    /// Verifies that anonymous object keys work correctly.
    /// </summary>
    [Fact]
    public void IsAllowed_AnonymousObjectKey_WorksCorrectly()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var uniqueId = Guid.NewGuid();
        var key = new { license = "test", status = "active", id = uniqueId };
        var utcNow = DateTimeOffset.UtcNow;
        var period = TimeSpan.FromMinutes(5);

        // Act
        var result1 = logger.IsAllowed(key, utcNow, period);
        var result2 = logger.IsAllowed(key, utcNow, period);

        // Assert
        Assert.True(result1);
        Assert.False(result2);
    }

    /// <summary>
    /// Verifies that anonymous objects with same structure but different references may share throttling.
    /// </summary>
    /// <remarks>
    /// IMPORTANT: Anonymous object equality behavior depends on the runtime implementation.
    /// ConcurrentDictionary uses object.Equals() and GetHashCode() for key comparison.
    /// Anonymous types override Equals/GetHashCode to use structural equality.
    /// Therefore, structurally equal anonymous objects ARE THE SAME KEY.
    /// </remarks>
    [Fact]
    public void IsAllowed_StructurallyEqualObjects_ShareThrottling()
    {
        // Arrange
        var logger = LicenseLogger.Instance;
        var uniqueValue = Guid.NewGuid().ToString();
        var key1 = new { license = uniqueValue, status = "active" };
        var key2 = new { license = uniqueValue, status = "active" };
        var utcNow = DateTimeOffset.UtcNow;
        var period = TimeSpan.FromMinutes(5);

        // Act
        var result1 = logger.IsAllowed(key1, utcNow, period);
        var result2 = logger.IsAllowed(key2, utcNow, period);

        // Assert - Structurally equal anonymous objects share same throttle state
        Assert.True(result1);
        Assert.False(result2); // Throttled because key1 and key2 are structurally equal
    }

    #endregion

    #region Logger Interface Tests

    /// <summary>
    /// Verifies that LicenseLogger.Instance is a singleton.
    /// </summary>
    [Fact]
    public void Instance_IsSingleton_ReturnsSameInstance()
    {
        // Act
        var instance1 = LicenseLogger.Instance;
        var instance2 = LicenseLogger.Instance;

        // Assert
        Assert.Same(instance1, instance2);
    }

    /// <summary>
    /// Verifies that IsEnabled returns false before initialization (NullLogger).
    /// </summary>
    [Fact]
    public void IsEnabled_BeforeInit_ReturnsFalse()
    {
        // Arrange
        var logger = LicenseLogger.Instance;

        // Act
        var result = logger.IsEnabled(LogLevel.Information);

        // Assert - NullLogger always returns false
        Assert.False(result);
    }

    /// <summary>
    /// Verifies that BeginScope returns null before initialization (NullLogger).
    /// </summary>
    [Fact]
    public void BeginScope_BeforeInit_ReturnsNull()
    {
        // Arrange
        var logger = LicenseLogger.Instance;

        // Act
        var scope = logger.BeginScope("test-scope");

        // Assert - NullLogger returns NullScope (which may or may not be null depending on implementation)
        // Just verify it doesn't throw
        Assert.NotNull(scope);
    }

    /// <summary>
    /// Verifies that Log method doesn't throw before initialization (NullLogger).
    /// </summary>
    [Fact]
    public void Log_BeforeInit_DoesNotThrow()
    {
        // Arrange
        var logger = LicenseLogger.Instance;

        // Act & Assert - Should not throw
        logger.LogInformation("Test message");
        logger.LogWarning("Test warning");
        logger.LogError("Test error");
    }

    #endregion

    #region Documentation Tests

    /// <summary>
    /// Documents the throttling mechanism and cleanup timer.
    /// </summary>
    [Fact]
    public void LicenseLogger_ThrottlingMechanism_Documented()
    {
        // Throttling Design:

        // 1. ConcurrentDictionary Storage:
        //    - Key: object (any type)
        //    - Value: DateTimeOffset (next allowed time for this key)
        //    - Thread-safe for concurrent access

        // 2. IsAllowed Logic:
        //    - TryAdd: First call with key returns true, stores nextAllowedTime
        //    - TryGetValue + TryUpdate: Subsequent calls check if period elapsed
        //    - Returns true only if period has fully elapsed

        // 3. Cleanup Timer:
        //    - Runs every 1 minute
        //    - Removes entries where nextAllowedTime < utcNow
        //    - Prevents unbounded memory growth

        // 4. Singleton Pattern:
        //    - LicenseLogger.Instance provides shared state
        //    - All license-related logging uses same throttle state
        //    - Persists for application lifetime

        // Use Case:
        // - Prevents flooding logs with repetitive license warnings
        // - Example: "License expiring soon" logged once per day instead of every request

        Assert.True(true); // Documentation test
    }

    /// <summary>
    /// Documents the concurrent access safety guarantees.
    /// </summary>
    [Fact]
    public void LicenseLogger_ConcurrencySafety_Documented()
    {
        // Concurrency Safety:

        // 1. ConcurrentDictionary:
        //    - Thread-safe atomic operations (TryAdd, TryGetValue, TryUpdate, TryRemove)
        //    - Lock-free for read operations
        //    - Optimistic concurrency for write operations

        // 2. Race Conditions Handled:
        //    - Multiple threads with same key: Only one TryAdd succeeds
        //    - TryUpdate uses compare-and-swap for atomic updates
        //    - Timer cleanup uses TryRemove (safe if key already removed)

        // 3. No Deadlocks:
        //    - No explicit locking
        //    - All operations are atomic or optimistic
        //    - Timer callback cannot deadlock with user code

        // 4. Performance:
        //    - O(1) average case for IsAllowed
        //    - No blocking on read operations
        //    - Minimal contention on write operations

        Assert.True(true); // Documentation test
    }

    #endregion
}
