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

using System.Text.Json;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// A model binder that uses JSON serialization to bind data to objects.
/// </summary>
/// <remarks>
/// This model binder utilizes the System.Text.Json.JsonSerializer to deserialize
/// the incoming data into the specified type. It is particularly useful for scenarios
/// where the incoming request data is in JSON format and needs to be converted into
/// complex objects. This binder can be applied to various types of data sources such as
/// query strings, form data, or headers, allowing for flexible data binding from JSON content.
/// </remarks>
public class JsonSerializerModelBinder : ModelBinderBase
{
    /// <summary>
    /// Attempts to parse the incoming data and convert it to the specified type using JSON deserialization.
    /// </summary>
    /// <param name="type">The type of object to which the data should be bound.</param>
    /// <param name="values">The data to be bound, represented as a collection of string values.</param>
    /// <param name="result">The resulting object after deserialization, if successful.</param>
    /// <returns>Returns true if deserialization is successful; otherwise, false.</returns>
    protected override bool TryParse(Type type, StringValues values, out object? result)
    {
        string? stringValue = values;
        if (stringValue == null)
        {
            result = null;
            return false;
        }

        result = JsonSerializer.Deserialize(stringValue, type);
        return true;
    }
}
