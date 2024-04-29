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
