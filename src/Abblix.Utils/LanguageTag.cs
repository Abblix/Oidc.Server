// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Diagnostics.CodeAnalysis;
using System.Globalization;

namespace Abblix.Utils;

/// <summary>
/// Reads a BCP 47 language tag, such as an entry of <c>ui_locales</c> or <c>claims_locales</c>, as the culture it
/// names.
/// </summary>
/// <remarks>
/// One check for every place a tag arrives, so a request is answered alike however it carries the tag. A tag names a
/// language only when .NET knows the name and the culture built from it has a name of its own: <c>und</c> and
/// <c>x-iv</c> build a culture with an empty name, which names no language a page could be shown in.
/// </remarks>
public static class LanguageTag
{
    /// <summary>
    /// The culture <paramref name="tag"/> names, when it names a language.
    /// </summary>
    /// <param name="tag">The language tag as sent.</param>
    /// <param name="culture">The culture the tag names, or null when it names none.</param>
    /// <returns>True when the tag names a language.</returns>
    public static bool TryParse(string tag, [NotNullWhen(true)] out CultureInfo? culture)
    {
        // CultureInfo offers no way to ask whether a name is one without constructing it
        try
        {
            culture = new CultureInfo(tag);
        }
        catch (CultureNotFoundException)
        {
            culture = null;
            return false;
        }

        if (culture.Name.Length == 0)
        {
            culture = null;
            return false;
        }

        return true;
    }
}
