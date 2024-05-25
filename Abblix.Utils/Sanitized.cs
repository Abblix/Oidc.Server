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
    /// Initializes a new instance of the <see cref="Sanitized"/> struct with the specified source string.
    /// </summary>
    /// <param name="source">The source string to be sanitized.</param>
    public Sanitized(object? source)
    {
        _source = source;
    }

    private readonly object? _source;

    /// <summary>
    /// Returns the sanitized string representation of the source string.
    /// </summary>
    /// <returns>A sanitized string with control characters removed and special characters escaped.</returns>
    public override string? ToString()
    {
        if (_source == null)
            return null;

        var source = _source.ToString();
        if (string.IsNullOrEmpty(source))
        {
            return source;
        }

        StringBuilder? builder = null;
        for (var i = 0; i < source.Length; i++)
        {
            var c = source[i];

            switch (c)
            {
                case '\n':
                    ReplaceTo("\\n", ref builder, source, i);
                    break;
                case '\r':
                    ReplaceTo("\\r", ref builder, source, i);
                    break;
                case '\t':
                    ReplaceTo("\\t", ref builder, source, i);
                    break;
                case '\"':
                    ReplaceTo("\\\"", ref builder, source, i);
                    break;
                case '\'':
                    ReplaceTo("\\'", ref builder, source, i);
                    break;
                case '\\':
                    ReplaceTo(@"\\", ref builder, source, i);
                    break;
                case ',':
                    ReplaceTo("\\,", ref builder, source, i);
                    break;
                case ';':
                    ReplaceTo("\\;", ref builder, source, i);
                    break;
                default:
                    if (0x00 <= c && c <= 0x1f || c == 0x7f)
                        ReplaceTo(null, ref builder, source, i);
                    else
                        builder?.Append(c);
                    break;
            }
        }

        return builder != null ? builder.ToString() : source;
    }

    private void ReplaceTo(string? replacement, ref StringBuilder? builder, string source, int i)
    {
        builder ??= new StringBuilder(source, 0, i, source.Length + (replacement?.Length ?? 0) - 1);
        builder.Append(replacement);
    }
}
