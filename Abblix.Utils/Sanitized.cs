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
    /// Gets the source object that will be sanitized when converted to string.
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
}
