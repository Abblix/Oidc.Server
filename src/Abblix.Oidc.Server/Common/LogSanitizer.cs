// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Helpers for safely emitting user-controlled values into logs.
/// </summary>
internal static class LogSanitizer
{
    /// <summary>
    /// Removes carriage-return and line-feed characters from a user-controlled value before it is
    /// written to a log.
    /// </summary>
    /// <remarks>
    /// A plain-text log sink (e.g. the default console logger) renders a structured-logging
    /// parameter inline into the message line, so a newline in an attacker-supplied value - such as
    /// an <c>auth_req_id</c> echoed back on a poll, or a requested scope - would forge an extra log
    /// line (CRLF injection / log forging). As a library we do not control the host's sink, so we
    /// strip the line breaks at the source to neutralize this regardless of how the host logs.
    /// </remarks>
    /// <param name="value">The user-controlled value about to be logged.</param>
    /// <returns>The value with all CR and LF characters removed.</returns>
    public static string Sanitized(this string value)
        => value.Replace("\r", string.Empty).Replace("\n", string.Empty);
}
