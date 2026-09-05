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
/// Provides extension methods for handling JSON data within JWTs.
/// </summary>
public static class JsonWebTokenExtensions
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

    /// <summary>
    /// Retrieves an array of strings from a <see cref="JsonObject"/> based on a specified property name.
    /// This method supports both single string values and arrays of strings.
    /// </summary>
    /// <param name="json">The <see cref="JsonObject"/> from which to retrieve the array of strings.</param>
    /// <param name="name">The property name to retrieve the values from.</param>
    /// <returns>An enumerable of strings if the property exists; otherwise, an empty enumerable.</returns>
    /// <remarks>
    /// This method is useful for JWT claims or other JSON structures where a property may contain either
    /// a single string value or an array of strings.
    /// </remarks>
    public static IEnumerable<string> GetArrayOfStrings(this JsonObject json, string name)
        => json.TryGetPropertyValue(name, out var property) ? GetArrayOfStrings(property) : [];

    /// <summary>
    /// Retrieves an array of strings from a <see cref="JsonObject"/> based on a specified property name,
    /// or returns <c>null</c> if the property does not exist.
    /// </summary>
    /// <param name="json">The <see cref="JsonObject"/> from which to retrieve the array of strings.</param>
    /// <param name="name">The property name to retrieve the values from.</param>
    /// <returns>
    /// An enumerable of strings if the property exists; otherwise, <c>null</c>.
    /// </returns>
    /// <remarks>
    /// This method is useful when distinguishing between a missing property (<c>null</c>) and a property
    /// that is present but empty. It supports both single string values and arrays of strings.
    /// </remarks>
    public static IEnumerable<string>? GetArrayOfStringsOrNull(this JsonObject json, string name)
        => json.TryGetPropertyValue(name, out var property) ? GetArrayOfStrings(property) : null;

    /// <summary>
    /// Parses a <see cref="JsonNode"/> as a collection of strings, supporting both single string values and JSON arrays.
    /// </summary>
    /// <param name="property">The <see cref="JsonNode"/> to parse.</param>
    /// <returns>
    /// An enumerable of strings extracted from the node. If the node is a single string, it yields one item;
    /// if it is a JSON array, it yields all string elements; if <c>null</c>, yields nothing.
    /// </returns>
    /// <remarks>
    /// This method is intended for internal use in scenarios like JWT claim parsing or generic JSON processing
    /// where string values might be encoded as either a single value or an array.
    /// </remarks>
    private static IEnumerable<string> GetArrayOfStrings(JsonNode? property)
    {
        // A node that is not a string yields nothing rather than throwing. These members are read off
        // objects shaped by whoever sent them - a JWT payload and an authorization_details entry are both
        // schemaless on the wire - so a number or an object can arrive where a string was expected, and
        // GetValue<string> answers that with an InvalidOperationException from inside a property getter.
        // Yielding nothing leaves the member unstated, which whatever requires it then refuses in
        // protocol language, at the layer that owns that decision.
        switch (property)
        {
            case null:
                break;

            case JsonValue value:
                if (value.TryGetValue<string>(out var single))
                    yield return single;
                break;

            case JsonArray array:
                foreach (var node in array.OfType<JsonValue>())
                {
                    if (node.TryGetValue<string>(out var element))
                        yield return element;
                }

                break;
        }
    }

    /// <summary>
    /// Sets a property in a <see cref="JsonObject"/> with a value that can be either a single string or an array of strings,
    /// depending on the number of items in the provided enumerable.
    /// </summary>
    /// <param name="json">The <see cref="JsonObject"/> to modify.</param>
    /// <param name="name">The name of the property to set.</param>
    /// <param name="values">The enumerable of string values to set as the property's value.</param>
    /// <remarks>
    /// This method is versatile for JWT or JSON handling where a property may accept both single and multiple values.
    /// </remarks>
    public static void SetArrayOrString(this JsonObject json, string name, IEnumerable<string> values)
    {
        json.SetProperty(name, values.ToJsonNode());
    }

    /// <summary>
    /// Sets a property on a <see cref="JsonObject"/> to either a single string, a JSON array of strings, or <c>null</c>,
    /// depending on the contents of the provided <paramref name="values"/> collection.
    /// </summary>
    /// <param name="json">The <see cref="JsonObject"/> to update.</param>
    /// <param name="name">The name of the property to set.</param>
    /// <param name="values">
    /// The collection of string values to assign. If <c>null</c>, the property is set to <c>null</c>.
    /// If the collection contains a single value, it is stored as a string; if multiple values, as a JSON array.
    /// </param>
    /// <remarks>
    /// This method is useful for serializing claims or properties where the value can be a single string,
    /// an array of strings, or omitted entirely (null), such as in JWT payloads or OpenID Connect claims.
    /// </remarks>
    public static void SetArrayOrStringOrNull(this JsonObject json, string name, IEnumerable<string>? values)
    {
        json.SetProperty(name, values?.ToJsonNode());
    }

    /// <summary>
    /// Assigns a collection of strings to a property as a JSON array whatever its length, or removes the
    /// property when the collection is <c>null</c> or empty.
    /// </summary>
    /// <param name="json">The object to write to.</param>
    /// <param name="name">The name of the property.</param>
    /// <param name="values">The values to assign, or <c>null</c> to remove the property.</param>
    /// <remarks>
    /// The single-element case is the whole difference from <see cref="SetArrayOrStringOrNull"/>, and it
    /// is why both exist. A JWT claim a specification defines as "a string or an array of strings" - aud,
    /// per RFC 7519 Section 4.1.3 - may collapse; a member defined as "an array of strings" may not, and
    /// writing a bare string there produces a document that parses and does not conform. Neither reader
    /// complains, so the divergence is only ever noticed by the party that rejects the token.
    /// </remarks>
    public static void SetArrayOrNull(this JsonObject json, string name, IEnumerable<string>? values)
    {
        var array = values is null
            ? null
            : new JsonArray(values.Select(value => (JsonNode?)JsonValue.Create(value)).ToArray());

        json.SetProperty(name, array is { Count: > 0 } ? array : null);
    }

    /// <summary>
    /// Converts a collection of strings to a JSON node, which will be either a single JSON value if there's only one string,
    /// or a JSON array if there are multiple strings.
    /// </summary>
    /// <param name="values">The collection of strings to convert.</param>
    /// <returns>A <see cref="JsonNode"/> representing either a single value or an array of strings, or null if the collection is empty.</returns>
    private static JsonNode? ToJsonNode(this IEnumerable<string> values)
    {
        using var enumerator = values.GetEnumerator();

        if (!enumerator.MoveNext())
            return null;

        var firstValue = enumerator.Current;

        if (!enumerator.MoveNext())
            return JsonValue.Create(firstValue);

        var array = new JsonArray { firstValue };

        do array.Add(enumerator.Current);
        while (enumerator.MoveNext());

        return array;
    }

    /// <summary>
    /// Retrieves a collection of strings from a space-separated string stored in a specified property of a <see cref="JsonObject"/>.
    /// </summary>
    /// <param name="json">The <see cref="JsonObject"/> from which to retrieve the space-separated strings.</param>
    /// <param name="name">The name of the property containing the space-separated string.</param>
    /// <returns>An enumerable of strings if the property exists and contains values; otherwise, an empty enumerable.</returns>
    /// <remarks>
    /// This method simplifies extracting multiple values from a single string property, common in JWT and OAuth scenarios.
    /// </remarks>
    public static IEnumerable<string> GetSpaceSeparatedStrings(this JsonObject json, string name)
    {
        var values = json.GetProperty<string>(name);
        return values.HasValue()
            ? values.Split(' ', StringSplitOptions.RemoveEmptyEntries)
            : Enumerable.Empty<string>();
    }

    /// <summary>
    /// Sets a property in a <see cref="JsonObject"/> with a value represented as a space-separated string from an enumerable of strings.
    /// </summary>
    /// <param name="json">The <see cref="JsonObject"/> to modify.</param>
    /// <param name="name">The name of the property to set.</param>
    /// <param name="value">The enumerable of string values to join into a space-separated string.</param>
    /// <returns>The modified <see cref="JsonObject"/>.</returns>
    /// <remarks>
    /// This method is useful for setting JWT claims or other JSON properties that accept a list of values as a single space-separated string.
    /// </remarks>
    public static void SetSpaceSeparatedStrings(this JsonObject json, string name, IEnumerable<string> value)
    {
        json.SetProperty(name, string.Join(' ', value));
    }

    /// <summary>
    /// A static <see cref="JsonElement"/> representing a null value in JSON.
    /// This is used as a default value when a null JSON node needs to be represented as a <see cref="JsonElement"/>.
    /// </summary>
    private static readonly JsonElement NullJsonElement = "null".ToJsonElement();

    /// <summary>
    /// Converts a JsonNode to a JsonElement.
    /// </summary>
    /// <param name="jsonNode">The JsonNode to convert.</param>
    /// <returns>The converted JsonElement.</returns>
    public static JsonElement ToJsonElement(this JsonNode? jsonNode)
    {
        return jsonNode == null ? NullJsonElement : jsonNode.ToJsonString().ToJsonElement();
    }

    /// <summary>
    /// Converts a JSON string to a <see cref="JsonElement"/>.
    /// </summary>
    /// <param name="jsonString">The JSON string to convert.</param>
    /// <returns>A <see cref="JsonElement"/> representing the parsed JSON structure.</returns>
    /// <exception cref="JsonException">
    /// Thrown when the JSON string is malformed and cannot be parsed.
    /// </exception>
    /// <remarks>
    /// This method is useful for converting a JSON string into a <see cref="JsonElement"/>,
    /// allowing for easy manipulation and traversal of the JSON structure.
    /// </remarks>
    private static JsonElement ToJsonElement(this string jsonString)
        => JsonDocument.Parse(jsonString).RootElement;

    /// <summary>
    /// Converts a JsonElement to a JsonNode, allowing for more dynamic manipulation of the JSON structure.
    /// </summary>
    /// <param name="jsonElement">The JsonElement to convert.</param>
    /// <returns>The converted JsonNode.</returns>
    /// <remarks>
    /// This method is useful when you need to convert from a structured JsonElement to a more flexible JsonNode.
    /// </remarks>
    public static JsonNode? ToJsonNode(this JsonElement jsonElement)
        => JsonNode.Parse(jsonElement.GetRawText());
}
