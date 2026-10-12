// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json;
using System.Text.Json.Serialization;

namespace Abblix.Utils.Json;

/// <summary>
/// A custom JSON converter for handling <see cref="DateTimeOffset"/> objects.
/// Converts to and from Unix time, which is the number of seconds that have elapsed since 00:00:00 UTC on 1 January 1970.
/// </summary>
public class DateTimeOffsetUnixTimeSecondsConverter: JsonConverter<DateTimeOffset>
{
    private static readonly long EarliestSeconds = DateTimeOffset.MinValue.ToUnixTimeSeconds();
    private static readonly long LatestSeconds = DateTimeOffset.MaxValue.ToUnixTimeSeconds();

    /// <summary>
    /// Reads and converts the JSON to a <see cref="DateTimeOffset"/> object.
    /// </summary>
    /// <param name="reader">The reader to read JSON from.</param>
    /// <param name="typeToConvert">The type of object to convert to.</param>
    /// <param name="options">Options for the serializer.</param>
    /// <returns>A <see cref="DateTimeOffset"/> object.</returns>
    /// <remarks>
    /// A Unix time is a NumericDate (RFC 7519 section 2), which may carry a fraction of a second; the fraction is
    /// dropped, as the instant is kept to the second.
    /// </remarks>
    /// <exception cref="JsonException">
    /// Thrown when the token is not a number, or names a time no <see cref="DateTimeOffset"/> can hold.
    /// </exception>
    public override DateTimeOffset Read(ref Utf8JsonReader reader, Type typeToConvert, JsonSerializerOptions options)
    {
        var seconds = reader.TryGetInt64(out var whole) ? whole : Math.Truncate(reader.GetDouble());
        if (seconds < EarliestSeconds || LatestSeconds < seconds)
            throw new JsonException($"{seconds} is not a Unix time an instant can have");

        return DateTimeOffset.FromUnixTimeSeconds((long)seconds);
    }

    /// <summary>
    /// Writes a <see cref="DateTimeOffset"/> object as a Unix time (number of seconds since Unix epoch) to JSON.
    /// </summary>
    /// <param name="writer">The writer to write JSON to.</param>
    /// <param name="value">The <see cref="DateTimeOffset"/> value to write.</param>
    /// <param name="options">Options for the serializer.</param>
    public override void Write(Utf8JsonWriter writer, DateTimeOffset value, JsonSerializerOptions options)
        => writer.WriteNumberValue(value.ToUnixTimeSeconds());
}
