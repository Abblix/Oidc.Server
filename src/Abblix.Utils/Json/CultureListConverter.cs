// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Globalization;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace Abblix.Utils.Json;

/// <summary>
/// Reads a list of language tags given either as one space-separated string or as an array of strings, and writes it
/// as an array.
/// </summary>
/// <remarks>
/// OpenID Connect gives <c>ui_locales</c> and <c>claims_locales</c> as a space-separated string, and a request object
/// carries them in that shape; an array is read as well, since clients send one. Every entry has to name a culture,
/// so an absent entry is refused rather than kept as a gap the list would carry on to whoever stores it.
/// </remarks>
public class CultureListConverter : JsonConverter<CultureInfo[]?>
{
    private static readonly ArrayConverter<CultureInfo, CultureInfoConverter> Elements = new();

    /// <inheritdoc />
    /// <exception cref="JsonException">
    /// Thrown when the token is neither a string nor an array, or an entry is absent or names no culture.
    /// </exception>
    public override CultureInfo[]? Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        if (reader.TokenType == JsonTokenType.String)
        {
            return reader.GetString()
                .NotNull("reader.GetString() != null")
                .Split(' ', StringSplitOptions.RemoveEmptyEntries)
                .Select(CultureInfoConverter.FromName)
                .ToArray();
        }

        // The serializer answers a JSON null for this list itself, so the array converter only ever sees an array
        var cultures = Elements.Read(ref reader, typeToConvert, options).NotNull(nameof(Elements));

        // An absent entry, or an empty one that would read as the invariant culture, names no language at all
        var named = cultures.OfType<CultureInfo>().Where(culture => culture.Name.Length > 0).ToArray();
        return named.Length == cultures.Length
            ? named
            : throw new JsonException("A list of language tags has an entry that names no culture");
    }

    /// <inheritdoc />
    public override void Write(Utf8JsonWriter writer, CultureInfo[]? value, JsonSerializerOptions options)
        => Elements.Write(writer, value, options);
}
