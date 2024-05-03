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

using System.Globalization;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Primitives;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// A model binder for binding culture information from model data.
/// </summary>
/// <remarks>
/// This binder is capable of handling culture-specific data by converting string values into <see cref="CultureInfo"/> objects.
/// It supports binding single <see cref="CultureInfo"/> objects, arrays, and lists of <see cref="CultureInfo"/>.
/// </remarks>
public class CultureInfoBinder : ModelBinderBase, IModelBinderProvider
{
    /// <summary>
    /// Gets the model binder based on the provided context.
    /// </summary>
    /// <param name="context">The context for the model binding.</param>
    /// <returns>The model binder for <see cref="CultureInfo"/>, or null if the model type is not supported.</returns>
    public IModelBinder? GetBinder(ModelBinderProviderContext context)
    {
        var type = context.Metadata.ModelType;

        return type == typeof(CultureInfo) ||
                type.IsAssignableFrom(typeof(CultureInfo[])) ||
                type.IsAssignableFrom(typeof(List<CultureInfo>))
            ? this
            : null;
    }

    /// <summary>
    /// Tries to parse the provided values into a <see cref="CultureInfo"/> object or a collection of <see cref="CultureInfo"/>.
    /// </summary>
    /// <param name="type">The target type for the binding.</param>
    /// <param name="values">The values to parse.</param>
    /// <param name="result">The parsed result object.</param>
    /// <returns>True if parsing is successful, otherwise false.</returns>
    protected override bool TryParse(Type type, StringValues values, out object? result)
    {
        string? stringValue = values;
        if (stringValue == null)
        {
            result = null;
            return false;
        }

        if (type == typeof(CultureInfo))
        {
            result = new CultureInfo(stringValue);
            return true;
        }

        if (type.IsAssignableFrom(typeof(CultureInfo[])))
        {
            result = GetCultureInfos(values).ToArray();
            return true;
        }

        if (type.IsAssignableFrom(typeof(List<CultureInfo>)))
        {
            result = GetCultureInfos(values).ToList();
            return true;
        }

        result = null;
        return false;
    }

    /// <summary>
    /// Extracts an enumerable of <see cref="CultureInfo"/> objects from the given string values.
    /// </summary>
    /// <param name="values">The string values to parse.</param>
    /// <returns>An enumerable of <see cref="CultureInfo"/>.</returns>
    private static IEnumerable<CultureInfo> GetCultureInfos(StringValues values) =>
        from value in values
        from culture in value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        select new CultureInfo(culture);
}
