// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;

namespace Abblix.Jwt;

/// <summary>
/// Provides extension methods for the <see cref="JsonObject"/> class, enhancing its usability
/// by simplifying the process of accessing and manipulating JSON properties.
/// </summary>
/// <remarks>
/// The extension methods in this class aim to streamline common tasks associated with JSON objects,
/// such as retrieving and setting properties with type safety and minimal boilerplate code. These methods
/// abstract away some of the complexities of working directly with <see cref="JsonObject"/> and <see cref="JsonNode"/>,
/// offering a more fluent and intuitive interface for developers.
/// </remarks>
public static class JsonObjectExtensions
{
    /// <summary>
    /// Retrieves the value of the specified property from a <see cref="JsonObject"/>.
    /// </summary>
    /// <param name="json">The <see cref="JsonObject"/> instance to extract the property value from.</param>
    /// <param name="name">The name of the property whose value is to be retrieved.</param>
    /// <typeparam name="T">The expected type of the property value.</typeparam>
    /// <returns>
    /// The value of the specified property if it exists and can be successfully converted to the specified type;
    /// otherwise, the default value for the type <typeparamref name="T"/>.
    /// </returns>
    /// <remarks>
    /// This method facilitates the retrieval of typed values from a JSON object, abstracting away the need
    /// for manual type checking and conversion.
    /// </remarks>
    public static T? GetProperty<T>(this JsonObject json, string name)
    {
        // A member that is present but is not the JSON type asked for reads as absent, which is what the
        // summary above has always promised and what every caller is written against. It matters because
        // the objects this reads are shaped by whoever sent the request: a JWT payload and an
        // authorization_details entry are both schemaless on the wire, so "type" can arrive as a number
        // and "locations" as a string. GetValue<T> answers that with an InvalidOperationException thrown
        // out of a property getter, which turns a request the specification answers with a named protocol
        // error into an unhandled one, in library code and in the per-type validators hosts write against
        // these same accessors.
        // Reading it as absent is not the same as accepting it. The member is then unstated, and whatever
        // requires it refuses the request in protocol language at the layer that owns that decision.
        return json.TryGetPropertyValue(name, out var value) && value is JsonValue typed
               && typed.TryGetValue<T>(out var result)
            ? result
            : default;
    }

    /// <summary>
    /// Sets or updates the value of a specified property in a <see cref="JsonObject"/>.
    /// </summary>
    /// <param name="json">The <see cref="JsonObject"/> instance to modify.</param>
    /// <param name="name">The name of the property to set or update.</param>
    /// <param name="value">The new value for the property. If <c>null</c>, the property is removed from the <see cref="JsonObject"/>.</param>
    /// <remarks>
    /// This method provides a convenient way to update the properties of a JSON object, allowing for
    /// the addition of new properties or the removal of existing ones by providing a <c>null</c> value.
    /// It ensures that the JSON object remains in a consistent state by avoiding the presence of null property values.
    /// </remarks>
    public static JsonObject SetProperty(this JsonObject json, string name, JsonNode? value)
    {
        if (value == null)
        {
            json.Remove(name);
        }
        else
        {
            json[name] = value;
        }

        return json;
    }
}
