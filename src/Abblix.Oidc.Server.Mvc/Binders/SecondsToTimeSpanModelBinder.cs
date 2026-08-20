// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.DeclarativeBinding;
using Abblix.Oidc.Server.Mvc.Attributes;
using Microsoft.Extensions.Primitives;
using Abblix.Utils;

namespace Abblix.Oidc.Server.Mvc.Binders;

/// <summary>
/// A model binder that converts seconds (as string) to a <see cref="TimeSpan"/> object.
/// </summary>
/// <remarks>
/// This model binder is useful for binding API parameters that are provided as seconds in string format,
/// and need to be converted to a <see cref="TimeSpan"/> for internal processing.
/// </remarks>
[Binds(typeof(TotalSecondsAttribute))]
public class SecondsToTimeSpanModelBinder : ModelBinderBase
{
    /// <summary>
    /// Attempts to parse the provided string value representing seconds into a <see cref="TimeSpan"/> object.
    /// </summary>
    /// <param name="type">The type of the model being bound. Expected to be <see cref="TimeSpan"/> or compatible.</param>
    /// <param name="values">The string values from the request, representing seconds.</param>
    /// <param name="result">The parsed <see cref="TimeSpan"/> object, if successful.</param>
    /// <returns>
    /// <c>true</c> if the parsing succeeds and a valid <see cref="TimeSpan"/> is created; otherwise, <c>false</c>.
    /// </returns>
    /// <remarks>
    /// This method parses the input string as a long, representing seconds, and converts it to a <see cref="TimeSpan"/>.
    /// If the input string is not a valid long or represents an invalid time duration, the parsing fails.
    /// </remarks>
    protected override bool TryParse(Type type, StringValues values, out object? result)
    {
        // The base binder returns before this is reached when the value provider held nothing, so a set with no
        // values cannot arrive here - and a set with values converts to a string. See ModelBinderBase.TryParse.
        var stringValue = ((string?)values).NotNull(nameof(values));

        result = TimeSpan.FromSeconds(long.Parse(stringValue));
        return true;
    }
}
