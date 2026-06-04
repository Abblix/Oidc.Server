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
    /// parameter inline into the message line, so a newline in an attacker-supplied value — such as
    /// an <c>auth_req_id</c> echoed back on a poll, or a requested scope — would forge an extra log
    /// line (CRLF injection / log forging). As a library we do not control the host's sink, so we
    /// strip the line breaks at the source to neutralize this regardless of how the host logs.
    /// </remarks>
    /// <param name="value">The user-controlled value about to be logged.</param>
    /// <returns>The value with all CR and LF characters removed.</returns>
    public static string Sanitized(this string value)
        => value.Replace("\r", string.Empty).Replace("\n", string.Empty);
}
