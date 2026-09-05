// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text;

namespace Abblix.Utils;

/// <summary>
/// A type that sanitizes a given string by removing control characters and escaping special characters
/// to prevent log injection attacks.
/// </summary>
public readonly record struct Sanitized
{
    /// <summary>
    /// Creates a new <see cref="Sanitized"/> instance with the specified source object.
    /// </summary>
    /// <param name="source">The source object to be sanitized when converted to string.</param>
    /// <returns>A new <see cref="Sanitized"/> instance.</returns>
    public static Sanitized Value(object? source) => new(source);

    /// <summary>
    /// Initializes a new instance of the <see cref="Sanitized"/> struct with the specified source.
    /// </summary>
    /// <param name="source">The source object to be sanitized.</param>
    private Sanitized(object? source)
    {
        Source = source;
    }

    /// <summary>
    /// The original, untrusted value. Sanitization is applied lazily inside <see cref="ToString"/>; reading this
    /// property directly bypasses sanitization and exposes raw input.
    /// </summary>
    public object? Source { get; init; }

    /// <summary>
    /// Returns the sanitized string representation of the source string.
    /// </summary>
    /// <returns>A sanitized string with control characters removed and special characters escaped.</returns>
    public override string ToString()
    {
        var source = Source?.ToString();
        if (string.IsNullOrEmpty(source))
            return string.Empty;

        StringBuilder? builder = null;
        for (var i = 0; i < source.Length; i++)
        {
            var c = source[i];

            var replacement = c switch
            {
                '\n' => "\\n",
                '\r' => "\\r",
                '\t' => "\\t",
                '\"' => "\\\"",
                '\'' => "\\'",
                '\\' => @"\\",
                ',' => "\\,",
                ';' => "\\;",
                _ => null
            };

            if (replacement != null)
            {
                builder ??= new StringBuilder(source, 0, i, source.Length + replacement.Length - 1);
                builder.Append(replacement);
            }
            else if (0x00 <= c && c <= 0x1f || c == 0x7f)
            {
                builder ??= new StringBuilder(source, 0, i, source.Length - 1);
            }
            else
            {
                builder?.Append(c);
            }
        }

        return builder?.ToString() ?? source;
    }

    /// <summary>Wraps a raw string in a <see cref="Sanitized"/> value so the
    /// stripping pass runs once at formatting time.</summary>
    /// <param name="source">The raw string to sanitize; may be <c>null</c>.</param>
    public static implicit operator Sanitized(string? source) => Value(source);

    /// <summary>Wraps a <see cref="Uri"/> in a <see cref="Sanitized"/> value so the
    /// stripping pass runs once at formatting time. The URI is converted to its string
    /// form before sanitization.</summary>
    /// <param name="source">The URI to sanitize; may be <c>null</c>.</param>
    public static implicit operator Sanitized(Uri? source) => Value(source);
}
