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
/// Reads a language tag, such as an entry of <c>ui_locales</c> or <c>claims_locales</c>, as a culture with a name
/// of its own.
/// </summary>
/// <remarks>
/// One reading for every place a tag or a list of tags arrives, so a request is answered alike however it carries
/// them. A tag is read only when .NET knows the name and the culture built from it has a name of its own:
/// <c>und</c> and <c>x-iv</c> build a culture with an empty name, which is written back as no name at all and
/// cannot be read again.
/// </remarks>
public static class LanguageTag
{
    /// <summary>
    /// Every culture a space-separated list of language tags names, as OpenID Connect gives <c>ui_locales</c> and
    /// <c>claims_locales</c>.
    /// </summary>
    /// <param name="list">The list as sent. Only a space separates two tags (OpenID Connect Core 1.0 section
    /// 3.1.2.1), so any other whitespace stays part of a tag and fails to read.</param>
    /// <param name="cultures">The cultures in the order given, or null when some tag cannot be read.</param>
    /// <returns>True when every tag in the list can be read.</returns>
    public static bool TryParseList(string list, [NotNullWhen(true)] out CultureInfo[]? cultures)
    {
        var tags = list.Split(' ', StringSplitOptions.RemoveEmptyEntries);
        var read = new CultureInfo[tags.Length];
        for (var index = 0; index < tags.Length; index++)
        {
            if (!TryParse(tags[index], out var culture))
            {
                cultures = null;
                return false;
            }

            read[index] = culture;
        }

        cultures = read;
        return true;
    }

    /// <summary>
    /// The culture <paramref name="tag"/> names, when .NET can build one with a name of its own from it.
    /// </summary>
    /// <param name="tag">The language tag as sent.</param>
    /// <param name="culture">The culture the tag names, or null when it names none.</param>
    /// <returns>True when the tag can be read.</returns>
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
