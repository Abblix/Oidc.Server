// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Common.Configuration;

/// <summary>
/// Refuses at startup a <see cref="OidcOptions.MaxRegistrationRequestSize"/> that no request could satisfy.
/// </summary>
/// <remarks>
/// A non-positive limit takes the endpoints down rather than bounding them, and it does so differently on each
/// host: an MVC host answers 413 to every registration, including a valid one of a few hundred bytes, while a
/// minimal API host hands the value to a server that rejects it and answers 500. Neither reads as a
/// configuration error at the point it surfaces, and both look to an operator like the endpoint being broken.
/// <para>
/// Zero is refused alongside a negative value because it means the same thing here: a request body always
/// carries at least the two braces of an empty JSON object. A deployment that wants no bound of ours clears
/// the option instead, which this validator lets through.
/// </para>
/// </remarks>
public sealed class RegistrationRequestSizeValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        if (options.MaxRegistrationRequestSize is not { } limit)
            return ValidateOptionsResult.Success;

        if (limit <= 0)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(OidcOptions.MaxRegistrationRequestSize)} is {limit}, which refuses every " +
                $"registration and update request instead of bounding them. Set a positive number of bytes, " +
                $"or clear it to leave the bound to the host.");
        }

        return ValidateOptionsResult.Success;
    }
}
