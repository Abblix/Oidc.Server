// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Reads and writes the NumericDate members of a JWT (RFC 7519 section 2): seconds since the epoch.
/// </summary>
public static class NumericDateExtensions
{
    /// <summary>
    /// Retrieves a <see cref="DateTimeOffset"/> value from a <see cref="JsonObject"/> based on
    /// a property stored as Unix time seconds.
    /// </summary>
    /// <param name="json">The <see cref="JsonObject"/> from which to retrieve the date/time value.</param>
    /// <param name="name">The property name containing the Unix time seconds.</param>
    /// <returns>
    /// A nullable <see cref="DateTimeOffset"/> representing the date and time of the specified property,
    /// or <c>null</c> if the property is not present.
    /// </returns>
    /// <remarks>
    /// Unix time seconds are widely used for representing date and time in JSON objects, especially in JWTs.
    /// This method simplifies retrieving such values by converting them directly to <see cref="DateTimeOffset"/>.
    /// A value that is present and cannot be read THROWS rather than answering null: a caller judging a token
    /// somebody else wrote reads through <see cref="JsonWebTokenPayload.TryReadTimestamp"/> instead, which
    /// names the claim in a refusal.
    /// </remarks>
    /// <exception cref="InvalidOperationException">The value is not a number.</exception>
    /// <exception cref="JsonException">The value is a JSON kind no number can be read from.</exception>
    /// <exception cref="ArgumentOutOfRangeException">The number is outside the range a date can hold.</exception>
    public static DateTimeOffset? GetUnixTimeSeconds(this JsonObject json, string name)
    {
        var node = json[name];
        if (node == null)
            return null;

        // A JsonValue parsed from text holds a JsonElement and converts to whatever numeric type is
        // asked for. One created in code holds the .NET primitive it was created from and answers
        // TryGetValue only for that exact type: a payload written as an int literal is a
        // JsonValue<int>, which says no to long. The two integral asks keep exactness for a value
        // past what a double represents; everything else goes through serialization, which reads
        // any numeric backing the same way rather than one primitive at a time - a list of
        // primitives is never complete, and the one left off it is the one a consumer writes.
        var value = node.AsValue();
        if (value.TryGetValue<int>(out var intValue))
            return DateTimeOffset.FromUnixTimeSeconds(intValue);

        if (value.TryGetValue<long>(out var seconds))
            return DateTimeOffset.FromUnixTimeSeconds(seconds);

        // RFC 7519 section 2 defines NumericDate as seconds since the epoch "other than that
        // non-integer values can be represented", and a JSON number written with an exponent is a
        // legal spelling of an integral one. Both arrive here as a double; the fraction is dropped
        // toward zero, since a token does not become valid or expire between two whole seconds. A
        // value that is not a number at all still fails the read, which is what a caller catching
        // it expects.
        var fractional = Math.Truncate(value.Deserialize<double>());
        if (fractional < long.MinValue || long.MaxValue < fractional)
            throw new ArgumentOutOfRangeException(name, fractional, "The value is outside the range a NumericDate can hold");

        return DateTimeOffset.FromUnixTimeSeconds((long)fractional);
    }

    /// <summary>
    /// Sets a <see cref="DateTimeOffset"/> value in a <see cref="JsonObject"/>, stored as Unix time seconds.
    /// </summary>
    /// <param name="json">The <see cref="JsonObject"/> to modify.</param>
    /// <param name="name">The property name under which to store the Unix time seconds.</param>
    /// <param name="value">The <see cref="DateTimeOffset"/> value to set. If <c>null</c>,
    ///     the property will be removed from the JSON object.</param>
    /// <returns>The modified <see cref="JsonObject"/>.</returns>
    /// <remarks>
    /// Storing dates as Unix time seconds is a common practice in JWTs and other JSON structures.
    /// This method facilitates setting such values by converting <see cref="DateTimeOffset"/> to Unix time seconds.
    /// </remarks>
    public static void SetUnixTimeSeconds(this JsonObject json, string name, DateTimeOffset? value)
    {
        var jsonValue = value.HasValue ? JsonValue.Create(value.Value.ToUnixTimeSeconds()) : null;
        json.SetProperty(name, jsonValue);
    }
}
