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
