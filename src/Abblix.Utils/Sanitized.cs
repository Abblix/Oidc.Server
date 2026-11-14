// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Collections.Frozen;
using System.Diagnostics.CodeAnalysis;
using System.Text;

namespace Abblix.Utils;

/// <summary>
/// A type that sanitizes a given string by removing control characters and escaping special characters
/// to prevent log injection attacks, and cuts it short so a crafted value cannot make a record of its own size.
/// </summary>
public readonly record struct Sanitized
{
    /// <summary>
    /// The most characters of the source written to the log. Long enough for an issuer, a redirect address or a key
    /// identifier a real party sends; of a longer value the first and the last half of it are kept, joined by
    /// <see cref="TruncationMark"/>, since where two addresses differ is as often at the end as at the start.
    /// </summary>
    internal const int MaxLength = 256;

    /// <summary>
    /// Stands where the middle of a value longer than <see cref="MaxLength"/> was left out, so a reader does not take
    /// the shortened value for the whole one.
    /// </summary>
    internal const string TruncationMark = "...";

    /// <summary>
    /// Written for an absent value, as the logging library writes a null argument, so an absent value and an empty
    /// one stay apart in the record.
    /// </summary>
    internal const string NullText = "(null)";

    /// <summary>
    /// Characters kept in escaped form. The line breaks and the tab are control characters too, and are escaped
    /// rather than stripped because the escape keeps them readable in the log.
    /// </summary>
    private static readonly FrozenDictionary<char, string> Escapes = new Dictionary<char, string>
    {
        ['\n'] = "\\n",
        ['\r'] = "\\r",
        ['\t'] = "\\t",
        ['\"'] = "\\\"",
        ['\''] = "\\'",
        ['\\'] = @"\\",
        [','] = "\\,",
        [';'] = "\\;",
    }.ToFrozenDictionary();

    /// <summary>
    /// Creates a new <see cref="Sanitized"/> instance with the specified source object.
    /// </summary>
    /// <param name="source">The source object to be sanitized when converted to string.</param>
    /// <returns>A new <see cref="Sanitized"/> instance.</returns>
    public static Sanitized Value(object? source) => new(source);

    /// <summary>
    /// Wraps each of <paramref name="sources"/>, so a list a sender chose is written as a list, each item sanitized
    /// on its own and the separators left to the logging library.
    /// </summary>
    /// <param name="sources">The values to be sanitized when converted to string; null for an absent list.</param>
    /// <returns>One <see cref="Sanitized"/> per source, in order; null for an absent list.</returns>
    [return: NotNullIfNotNull(nameof(sources))]
    public static Sanitized[]? Values(IEnumerable<object?>? sources) => sources?.Select(Value).ToArray();

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
        if (Source is null)
            return NullText;

        var source = Source.ToString();
        if (string.IsNullOrEmpty(source))
            return string.Empty;

        if (source.Length <= MaxLength)
            return Escape(source);

        return Escape(source[..HeadEnd(source)]) + TruncationMark + Escape(source[TailStart(source)..]);
    }

    /// <summary>
    /// Where the kept start of a long source ends: never between the two halves of a surrogate pair, which would
    /// leave a character that is not one.
    /// </summary>
    private static int HeadEnd(string source)
    {
        const int head = MaxLength / 2;
        return char.IsHighSurrogate(source[head - 1]) ? head - 1 : head;
    }

    /// <summary>
    /// Where the kept end of a long source starts, for the same reason never inside a surrogate pair.
    /// </summary>
    private static int TailStart(string source)
    {
        var tail = source.Length - MaxLength / 2;
        return char.IsLowSurrogate(source[tail]) ? tail + 1 : tail;
    }

    private static string Escape(string source)
    {
        // Copy-on-write: a clean string, the usual case, is returned as is and never copied.
        var firstUnsafe = IndexOfUnsafe(source);
        if (firstUnsafe < 0)
            return source;

        var builder = new StringBuilder(source, 0, firstUnsafe, source.Length);
        for (var i = firstUnsafe; i < source.Length; i++)
            AppendSanitized(builder, source[i]);

        return builder.ToString();
    }

    private static int IndexOfUnsafe(string source)
    {
        for (var i = 0; i < source.Length; i++)
        {
            if (Escapes.ContainsKey(source[i]) || IsStripped(source[i]))
                return i;
        }

        return -1;
    }

    private static void AppendSanitized(StringBuilder builder, char c)
    {
        if (Escapes.TryGetValue(c, out var replacement))
            builder.Append(replacement);
        else if (!IsStripped(c))
            builder.Append(c);
    }

    /// <summary>
    /// The C0 control characters and DEL, which are removed outright.
    /// </summary>
    private static bool IsStripped(char c) => c <= 0x1f || c == 0x7f;

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
