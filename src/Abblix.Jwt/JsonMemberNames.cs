// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// The rule a key and a key set hold their member names to.
/// </summary>
internal static class JsonMemberNames
{
    /// <summary>
    /// Refuses an object that names one of its members more than once.
    /// </summary>
    /// <remarks>
    /// RFC 7517 sections 4 and 5 let a parser either refuse a member named twice or take its last value, and refusing
    /// leaves no two parties reading one key differently. Checked on the parsed object rather than left to the
    /// serializer, which sees only the members a type maps: a key's <c>kty</c>, which picks its subtype, and every
    /// member the library does not know would pass it unchecked.
    /// </remarks>
    /// <param name="value">The object to check.</param>
    /// <param name="subject">What the object is, for the message.</param>
    /// <exception cref="JsonException">The object names a member more than once.</exception>
    public static void RefuseRepeated(JsonElement value, string subject)
    {
        var repeated = value.EnumerateObject()
            .Select(member => member.Name)
            .FindDuplicates(StringComparer.Ordinal)
            .FirstOrDefault();

        if (repeated is not null)
            throw new JsonException($"The {subject} names its member '{repeated}' more than once");
    }
}
