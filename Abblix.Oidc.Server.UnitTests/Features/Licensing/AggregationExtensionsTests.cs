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

using Abblix.Oidc.Server.Features.Licensing;

using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Licensing;

/// <summary>
/// Tests for AggregationExtensions methods used in license merging and comparison operations.
/// </summary>
public class AggregationExtensionsTests
{
    #region Greater<T> Tests

    /// <summary>
    /// Verifies that Greater returns null when both values are null, treating null as positive infinity.
    /// </summary>
    [Fact]
    public void Greater_BothNull_ReturnsNull()
    {
        // Arrange & Act
        var result = ((int?)null).Greater(null);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that Greater returns null when current value is null (positive infinity),
    /// regardless of accumulator value.
    /// </summary>
    [Theory]
    [InlineData(5)]
    [InlineData(100)]
    [InlineData(-50)]
    public void Greater_CurrentValueNull_ReturnsNull(int accumulatorValue)
    {
        // Arrange & Act
        var result = ((int?)accumulatorValue).Greater(null);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that Greater returns null when current value is provided but accumulator is already null (infinity).
    /// When currentValue is finite and accumulatorValue is null (infinity), null wins as the greater value.
    /// </summary>
    [Theory]
    [InlineData(5)]
    [InlineData(100)]
    [InlineData(-50)]
    public void Greater_AccumulatorNull_ReturnsNull(int currentValue)
    {
        // Arrange & Act
        var result = ((int?)null).Greater(currentValue);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that Greater returns current value when it's numerically larger than accumulator.
    /// </summary>
    [Theory]
    [InlineData(5, 10, 10)]
    [InlineData(100, 200, 200)]
    [InlineData(-50, -10, -10)]
    public void Greater_CurrentValueLarger_ReturnsCurrentValue(int accumulatorValue, int currentValue, int expected)
    {
        // Arrange & Act
        var result = ((int?)accumulatorValue).Greater(currentValue);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Verifies that Greater returns accumulator value when it's larger than or equal to current value.
    /// </summary>
    [Theory]
    [InlineData(10, 5, 10)]
    [InlineData(200, 100, 200)]
    [InlineData(-10, -50, -10)]
    [InlineData(50, 50, 50)] // Equal values
    public void Greater_AccumulatorLargerOrEqual_ReturnsAccumulatorValue(int accumulatorValue, int currentValue, int expected)
    {
        // Arrange & Act
        var result = ((int?)accumulatorValue).Greater(currentValue);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Verifies that Greater works correctly with DateTimeOffset type used in license expiration.
    /// </summary>
    [Fact]
    public void Greater_WithDateTimeOffset_WorksCorrectly()
    {
        // Arrange
        DateTimeOffset? earlier = DateTimeOffset.UtcNow;
        DateTimeOffset? later = earlier.Value.AddDays(1);

        // Act
        var result = earlier.Greater(later);

        // Assert
        Assert.Equal(later, result);
    }

    #endregion

    #region Lesser<T> Tests

    /// <summary>
    /// Verifies that Lesser returns null when both values are null, treating null as negative infinity.
    /// </summary>
    [Fact]
    public void Lesser_BothNull_ReturnsNull()
    {
        // Arrange & Act
        var result = ((int?)null).Lesser(null);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that Lesser returns current value when it's not null and accumulator is null (negative infinity).
    /// </summary>
    [Theory]
    [InlineData(5)]
    [InlineData(100)]
    [InlineData(-50)]
    public void Lesser_AccumulatorNull_ReturnsCurrentValue(int currentValue)
    {
        // Arrange & Act
        var result = ((int?)currentValue).Lesser(null);

        // Assert
        Assert.Equal(currentValue, result);
    }

    /// <summary>
    /// Verifies that Lesser returns accumulator when current value is null (negative infinity).
    /// When currentValue is null (negative infinity) and accumulatorValue is finite, accumulator is returned.
    /// </summary>
    [Theory]
    [InlineData(5)]
    [InlineData(100)]
    [InlineData(-50)]
    public void Lesser_CurrentValueNull_ReturnsAccumulator(int accumulatorValue)
    {
        // Arrange & Act
        var result = ((int?)null).Lesser(accumulatorValue);

        // Assert
        Assert.Equal(accumulatorValue, result);
    }

    /// <summary>
    /// Verifies that Lesser returns current value when it's smaller than accumulator.
    /// </summary>
    [Theory]
    [InlineData(10, 5, 5)]
    [InlineData(200, 100, 100)]
    [InlineData(-10, -50, -50)]
    public void Lesser_CurrentValueSmaller_ReturnsCurrentValue(int accumulatorValue, int currentValue, int expected)
    {
        // Arrange & Act
        var result = ((int?)accumulatorValue).Lesser(currentValue);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Verifies that Lesser returns accumulator value when it's smaller than or equal to current value.
    /// </summary>
    [Theory]
    [InlineData(5, 10, 5)]
    [InlineData(100, 200, 100)]
    [InlineData(-50, -10, -50)]
    [InlineData(50, 50, 50)] // Equal values
    public void Lesser_AccumulatorSmallerOrEqual_ReturnsAccumulatorValue(int accumulatorValue, int currentValue, int expected)
    {
        // Arrange & Act
        var result = ((int?)accumulatorValue).Lesser(currentValue);

        // Assert
        Assert.Equal(expected, result);
    }

    /// <summary>
    /// Verifies that Lesser works correctly with DateTimeOffset type used in license expiration dates.
    /// This is critical for finding the earliest expiration among multiple licenses.
    /// </summary>
    [Fact]
    public void Lesser_WithDateTimeOffset_ReturnsEarlierDate()
    {
        // Arrange
        DateTimeOffset? earlier = DateTimeOffset.UtcNow;
        DateTimeOffset? later = earlier.Value.AddDays(1);

        // Act
        var result = later.Lesser(earlier);

        // Assert
        Assert.Equal(earlier, result);
    }

    #endregion

    #region Join<T> Tests

    /// <summary>
    /// Verifies that Join returns null when both sets are null.
    /// </summary>
    [Fact]
    public void Join_BothNull_ReturnsNull()
    {
        // Arrange & Act
        var result = ((HashSet<string>?)null).Join(null);

        // Assert
        Assert.Null(result);
    }

    /// <summary>
    /// Verifies that Join returns accumulator when current set is null.
    /// </summary>
    [Fact]
    public void Join_CurrentNull_ReturnsAccumulator()
    {
        // Arrange
        var accumulator = new HashSet<string>(StringComparer.Ordinal) { "issuer1", "issuer2" };

        // Act
        var result = accumulator.Join(null);

        // Assert
        Assert.Same(accumulator, result);
    }

    /// <summary>
    /// Verifies that Join returns current set when accumulator is null.
    /// </summary>
    [Fact]
    public void Join_AccumulatorNull_ReturnsCurrent()
    {
        // Arrange
        var current = new HashSet<string>(StringComparer.Ordinal) { "issuer1", "issuer2" };

        // Act
        var result = ((HashSet<string>?)null).Join(current);

        // Assert
        Assert.Same(current, result);
    }

    /// <summary>
    /// Verifies that Join combines two sets with unique elements from both.
    /// </summary>
    [Fact]
    public void Join_TwoSetsWithUniqueElements_ReturnsUnion()
    {
        // Arrange
        var accumulator = new HashSet<string>(StringComparer.Ordinal) { "issuer1", "issuer2" };
        var current = new HashSet<string>(StringComparer.Ordinal) { "issuer3", "issuer4" };

        // Act
        var result = accumulator.Join(current);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(4, result.Count);
        Assert.Contains("issuer1", result);
        Assert.Contains("issuer2", result);
        Assert.Contains("issuer3", result);
        Assert.Contains("issuer4", result);
    }

    /// <summary>
    /// Verifies that Join removes duplicate elements when combining sets.
    /// </summary>
    [Fact]
    public void Join_TwoSetsWithDuplicates_ReturnsUniqueElements()
    {
        // Arrange
        var accumulator = new HashSet<string>(StringComparer.Ordinal) { "issuer1", "issuer2", "issuer3" };
        var current = new HashSet<string>(StringComparer.Ordinal) { "issuer2", "issuer3", "issuer4" };

        // Act
        var result = accumulator.Join(current);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(4, result.Count);
        Assert.Contains("issuer1", result);
        Assert.Contains("issuer2", result);
        Assert.Contains("issuer3", result);
        Assert.Contains("issuer4", result);
    }

    /// <summary>
    /// Verifies that Join preserves the comparer from the accumulator set.
    /// This is important for case-insensitive or culture-specific comparisons.
    /// </summary>
    [Fact]
    public void Join_PreservesComparerFromAccumulator()
    {
        // Arrange
        var accumulator = new HashSet<string>(StringComparer.OrdinalIgnoreCase) { "ISSUER1", "issuer2" };
        var current = new HashSet<string>(StringComparer.Ordinal) { "issuer1", "ISSUER3" };

        // Act
        var result = accumulator.Join(current);

        // Assert
        Assert.NotNull(result);
        Assert.Equal(StringComparer.OrdinalIgnoreCase, result.Comparer);
        // Should have only 3 elements because "ISSUER1" and "issuer1" are considered equal
        Assert.Equal(3, result.Count);
    }

    /// <summary>
    /// Verifies that Join works correctly with empty sets.
    /// </summary>
    [Fact]
    public void Join_WithEmptySets_WorksCorrectly()
    {
        // Arrange
        var empty1 = new HashSet<string>(StringComparer.Ordinal);
        var empty2 = new HashSet<string>(StringComparer.Ordinal);
        var nonEmpty = new HashSet<string>(StringComparer.Ordinal) { "issuer1" };

        // Act & Assert
        var result1 = empty1.Join(empty2);
        Assert.NotNull(result1);
        Assert.Empty(result1);

        var result2 = empty1.Join(nonEmpty);
        Assert.NotNull(result2);
        Assert.Single(result2);
        Assert.Contains("issuer1", result2);

        var result3 = nonEmpty.Join(empty2);
        Assert.NotNull(result3);
        Assert.Single(result3);
        Assert.Contains("issuer1", result3);
    }

    /// <summary>
    /// Verifies that Join creates a new HashSet and doesn't modify original sets.
    /// </summary>
    [Fact]
    public void Join_CreatesNewSet_DoesNotModifyOriginals()
    {
        // Arrange
        var accumulator = new HashSet<string>(StringComparer.Ordinal) { "issuer1", "issuer2" };
        var current = new HashSet<string>(StringComparer.Ordinal) { "issuer3", "issuer4" };
        var accumulatorCountBefore = accumulator.Count;
        var currentCountBefore = current.Count;

        // Act
        var result = accumulator.Join(current);

        // Assert
        Assert.NotSame(accumulator, result);
        Assert.NotSame(current, result);
        Assert.Equal(accumulatorCountBefore, accumulator.Count);
        Assert.Equal(currentCountBefore, current.Count);
    }

    #endregion

    #region Integration Tests

    /// <summary>
    /// Verifies that extension methods work together to simulate license aggregation logic.
    /// This simulates how LicenseManager combines multiple active licenses.
    /// </summary>
    [Fact]
    public void AggregationExtensions_IntegrationTest_SimulateLicenseMerging()
    {
        // Arrange - Simulate two active licenses
        int? clientLimit1 = 10;
        int? clientLimit2 = 20;

        DateTimeOffset? expiresAt1 = DateTimeOffset.UtcNow.AddDays(30);
        DateTimeOffset? expiresAt2 = DateTimeOffset.UtcNow.AddDays(60);

        var validIssuers1 = new HashSet<string>(StringComparer.Ordinal) { "https://issuer1.com", "https://issuer2.com" };
        var validIssuers2 = new HashSet<string>(StringComparer.Ordinal) { "https://issuer2.com", "https://issuer3.com" };

        // Act - Aggregate licenses (take max client limit, min expiration, union of issuers)
        var mergedClientLimit = clientLimit1.Greater(clientLimit2);
        var mergedExpiresAt = expiresAt1.Lesser(expiresAt2);
        var mergedValidIssuers = validIssuers1.Join(validIssuers2);

        // Assert
        Assert.Equal(20, mergedClientLimit); // Maximum client limit
        Assert.Equal(expiresAt1, mergedExpiresAt); // Earliest expiration
        Assert.NotNull(mergedValidIssuers);
        Assert.Equal(3, mergedValidIssuers.Count); // Union of issuers
        Assert.Contains("https://issuer1.com", mergedValidIssuers);
        Assert.Contains("https://issuer2.com", mergedValidIssuers);
        Assert.Contains("https://issuer3.com", mergedValidIssuers);
    }

    /// <summary>
    /// Verifies aggregation behavior when one license has unlimited limits (null values).
    /// Null represents "no limit" which is treated as infinity.
    /// </summary>
    [Fact]
    public void AggregationExtensions_WithUnlimitedLicense_TreatsNullAsInfinity()
    {
        // Arrange
        int? limitedClientLimit = 10;
        int? unlimitedClientLimit = null; // No limit

        // Act
        var result = limitedClientLimit.Greater(unlimitedClientLimit);

        // Assert - Unlimited (null) should win
        Assert.Null(result);
    }

    #endregion
}
