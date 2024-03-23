// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

namespace Abblix.Oidc.Server.Features.Licensing;

/// <summary>
/// Provides extension methods for aggregating values from objects based on specific comparable properties.
/// </summary>
public static class AggregationExtensions
{
    /// <summary>
    /// Determines the greater of two nullable values, treating null as positive infinity.
    /// </summary>
    /// <typeparam name="T">The type of the values being compared, constrained to value types that implement
    /// <see cref="IComparable{T}"/>.</typeparam>
    /// <param name="accumulatorValue">The first nullable value to compare.</param>
    /// <param name="currentValue">The second nullable value to compare.</param>
    /// <returns>The greater of the two values if at least one is non-null; otherwise, null. If both values are
    /// non-null, the method returns null only if the <paramref name="currentValue"/> is null, indicating it is
    /// considered as positive infinity.</returns>
    /// <remarks>
    /// This method is useful in scenarios where you're aggregating a collection of nullable values and consider
    /// the absence of a value (null) as the highest possible value, allowing for custom maximum value logic.
    /// </remarks>
    public static T? Greater<T>(this T? accumulatorValue, T? currentValue)
        where T : struct, IComparable<T>
    {
        if (currentValue.HasValue)
        {
            if (accumulatorValue.HasValue && accumulatorValue.Value.CompareTo(currentValue.Value) < 0)
            {
                return currentValue;
            }
        }
        else if (accumulatorValue.HasValue)
        {
            return null;
        }

        return accumulatorValue;
    }

    /// <summary>
    /// Determines the lesser of two nullable values, treating null as negative infinity.
    /// </summary>
    /// <typeparam name="T">The type of the values being compared, constrained to value types that implement
    /// <see cref="IComparable{T}"/>.</typeparam>
    /// <param name="currentValue">The first nullable value to compare.</param>
    /// <param name="accumulatorValue">The second nullable value to compare.</param>
    /// <returns>The lesser of the two values if at least one is non-null; otherwise, null. If both values are non-null,
    /// the method returns null only if the <paramref name="accumulatorValue"/> is null, indicating it is considered
    /// as negative infinity.</returns>
    /// <remarks>
    /// This method supports scenarios requiring aggregation of a series of nullable values where the absence of
    /// a value (null) is interpreted as the lowest possible value, enabling custom minimum value logic.
    /// </remarks>
    public static T? Lesser<T>(this T? currentValue, T? accumulatorValue)
        where T : struct, IComparable<T>
    {
        if (currentValue.HasValue)
        {
            if (!accumulatorValue.HasValue || currentValue.Value.CompareTo(accumulatorValue.Value) < 0)
            {
                return currentValue;
            }
        }

        return accumulatorValue;
    }

    /// <summary>
    /// Combines the elements of two hash sets into a single set, including all unique elements from both.
    /// </summary>
    /// <typeparam name="T">The type of elements in the hash sets.</typeparam>
    /// <param name="accumulator">The first hash set.</param>
    /// <param name="current">The second hash set to combine with the first.</param>
    /// <returns>A new hash set containing all unique elements from both input sets. If both inputs are null, returns null.</returns>
    /// <remarks>
    /// This method provides a convenient way to merge two sets of elements, ensuring that the result contains
    /// all distinct elements from both sets. It is particularly useful for combining collections of unique items
    /// without duplicating any elements.
    /// </remarks>
    public static HashSet<T>? Join<T>(this HashSet<T>? accumulator, HashSet<T>? current)
    {
        return (accumulator, current) switch
        {
            (null, null) => null,
            (not null, null) => accumulator,
            (null, not null) => current,
            (not null, not null) => accumulator.Concat(current).ToHashSet(accumulator.Comparer),
        };
    }
}
