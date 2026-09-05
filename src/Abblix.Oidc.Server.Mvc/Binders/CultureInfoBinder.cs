// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Globalization;
using Abblix.Oidc.Server.DeclarativeBinding;
using Abblix.Oidc.Server.Mvc.Attributes;
using Microsoft.AspNetCore.Mvc.ModelBinding;
using Microsoft.Extensions.Primitives;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// A model binder for binding culture information from model data.
/// </summary>
/// <remarks>
/// This binder is capable of handling culture-specific data by converting string values into <see cref="CultureInfo"/> objects.
/// It supports binding single <see cref="CultureInfo"/> objects, arrays, and lists of <see cref="CultureInfo"/>.
/// </remarks>
[Binds(typeof(CultureListAttribute))]
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
        // The base binder returns before this is reached when the value provider held nothing, so a set with no
        // values cannot arrive here - and a set with values converts to a string. See ModelBinderBase.TryParse.
        var stringValue = ((string?)values).NotNull(nameof(values));

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
        from value in values.OfType<string>()
        from culture in value.Split(' ', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries)
        select new CultureInfo(culture);
}
