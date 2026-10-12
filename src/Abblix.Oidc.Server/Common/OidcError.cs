// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

namespace Abblix.Oidc.Server.Common;

/// <summary>
/// Represents an error that occurred during OAuth 2.0/OpenID Connect request processing.
/// </summary>
/// <param name="Error">The error code indicating the nature of the error.</param>
/// <param name="ErrorDescription">A human-readable description of the error.</param>
public record OidcError(string Error, string ErrorDescription)
{
    /// <summary>
    /// A human-readable description of the error, made only of the characters RFC 6749 allows in it.
    /// </summary>
    /// <remarks>
    /// RFC 6749 (sections 4.1.2.1, 4.2.2.1 and 5.2): values for the error_description parameter "MUST NOT include
    /// characters outside the set %x20-21 / %x23-5B / %x5D-7E". A description often quotes what the client sent,
    /// so each character outside that set is replaced where the error is built rather than in each refusal, and
    /// <see cref="Endpoints.Authorization.Interfaces.AuthorizationError"/>, which an authorization response is also
    /// built as directly, does the same.
    /// </remarks>
    public string ErrorDescription { get; init => field = WithAllowedCharacters(value); } =
        WithAllowedCharacters(ErrorDescription);

    /// <summary>
    /// Replaces each character RFC 6749 keeps out of error_description with a question mark.
    /// </summary>
    internal static string WithAllowedCharacters(string description)
        => string.Create(description.Length, description, static (span, source) =>
        {
            for (var i = 0; i < source.Length; i++)
                span[i] = IsAllowed(source[i]) ? source[i] : Replacement;
        });

    private const char Replacement = '?';

    /// <summary>%x20-21 / %x23-5B / %x5D-7E: printable ASCII without the double quote and the backslash.</summary>
    private static bool IsAllowed(char character)
        => character is (>= '\x20' and <= '\x21') or (>= '\x23' and <= '\x5B') or (>= '\x5D' and <= '\x7E');
}
