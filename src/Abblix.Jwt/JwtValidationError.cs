// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Utils;

namespace Abblix.Jwt;

/// <summary>
/// Represents an error encountered during the validation of a JSON Web Token (JWT).
/// </summary>
/// <param name="Error">The specific type of JWT error encountered.</param>
/// <param name="ErrorDescription">A description of the error providing details about the validation failure.</param>
public record JwtValidationError(JwtError Error, string ErrorDescription)
{
    /// <summary>
    /// Formats a user-friendly description of the JWT validation error with proper sentence capitalization.
    /// </summary>
    /// <param name="forceLowercaseFirst">
    /// If true, converts the first letter to lowercase for embedding in larger sentences.
    /// If false, preserves the original capitalization. Default is true.
    /// </param>
    /// <returns>
    /// The error description, optionally with the first letter in lowercase if a description is available,
    /// otherwise returns the error code as a string.
    /// </returns>
    /// <remarks>
    /// This method is useful for embedding error descriptions in the middle of sentences,
    /// where starting with a lowercase letter maintains proper grammar.
    /// Example with forceLowercaseFirst=true: "The id token hint contains invalid token: token has expired"
    /// Example with forceLowercaseFirst=false: "Token has expired"
    /// </remarks>
    public string ToString(bool forceLowercaseFirst)
    {
        if (!ErrorDescription.HasValue())
            return Error.ToString();

        if (!forceLowercaseFirst || char.IsLower(ErrorDescription[0]))
            return ErrorDescription;

        return char.ToLowerInvariant(ErrorDescription[0]) + ErrorDescription[1..];
    }

    /// <summary>
    /// Returns the error description as the textual representation of this validation error,
    /// preserving the original capitalization of <see cref="ErrorDescription"/>.
    /// </summary>
    public override string ToString() => ToString(forceLowercaseFirst: false);
}
