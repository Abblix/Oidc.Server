// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils;

/// <summary>
/// Keeps an OAuth error description to the characters it may carry.
/// </summary>
/// <remarks>
/// RFC 6749 (sections 4.1.2.1, 4.2.2.1 and 5.2): values for the error_description parameter "MUST NOT include
/// characters outside the set %x20-21 / %x23-5B / %x5D-7E". A description often quotes what a client sent, so the
/// type an error is built as applies this once rather than each refusal escaping what it quotes. Unlike
/// <see cref="Sanitized"/>, which escapes for a log line with the backslash this set excludes, every character is
/// replaced one for one.
/// </remarks>
public static class OAuthErrorDescription
{
    private const char Replacement = '?';

    /// <summary>
    /// Replaces each character RFC 6749 keeps out of error_description with a question mark.
    /// </summary>
    /// <param name="description">The description as a refusal wrote it.</param>
    /// <returns>The description with each character outside the allowed set replaced.</returns>
    public static string Sanitize(string description)
        => string.Create(description.Length, description, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
                span[i] = IsAllowed(source[i]) ? source[i] : Replacement;
        });

    /// <summary>%x20-21 / %x23-5B / %x5D-7E: printable ASCII without the double quote and the backslash.</summary>
    private static bool IsAllowed(char character)
        => character is (>= '\x20' and <= '\x21') or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E');
}
