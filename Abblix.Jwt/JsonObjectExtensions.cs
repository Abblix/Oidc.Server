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
        return json.TryGetPropertyValue(name, out var value) && value != null
            ? value.GetValue<T>()
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
        if (json.TryGetPropertyValue(name, out _))
        {
            if (value == null)
                json.Remove(name);
        }
        else if (value != null)
        {
            json.Add(name, value);
        }

        return json;
    }
}
