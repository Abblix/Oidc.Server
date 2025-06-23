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
    /// or <c>null</c> if the property is not present or cannot be converted.
    /// </returns>
    /// <remarks>
    /// Unix time seconds are widely used for representing date and time in JSON objects, especially in JWTs.
    /// This method simplifies retrieving such values by converting them directly to <see cref="DateTimeOffset"/>.
    /// </remarks>
    public static DateTimeOffset? GetUnixTimeSeconds(this JsonObject json, string name)
    {
        var node = json[name];
        if (node == null)
            return null;

        var value = node.AsValue();
        var seconds = value.TryGetValue<int>(out var intValue) ? intValue : value.GetValue<long>();
        return DateTimeOffset.FromUnixTimeSeconds(seconds);
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
    {
        if (!json.TryGetPropertyValue(name, out var jsonNode))
            yield break;

        switch (jsonNode)
        {
            case null:
                break;

            case JsonValue value:
                yield return value.GetValue<string>();
                break;

            case JsonArray array:
                foreach (var element in array)
                    if (element != null)
                        yield return element.GetValue<string>();
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
