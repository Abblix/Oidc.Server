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
/// Refuses, while the host is still starting, grant types for new clients that are an empty set or hold a blank or
/// null value.
/// </summary>
/// <remarks>
/// Every registration is held to the set, so an empty one refuses each of them, and a blank or null value names no
/// grant type a client can request. Only those two are checked here: a misspelled value, or one padded with spaces,
/// still starts the host, and a client requesting that grant type is refused.
/// </remarks>
public sealed class NewClientGrantTypesValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        var allowed = options.NewClientOptions.AllowedGrantTypes;
        if (allowed is null)
            return ValidateOptionsResult.Success;

        const string setting = $"{nameof(OidcOptions.NewClientOptions)}.{nameof(NewClientOptions.AllowedGrantTypes)}";

        if (allowed.Length == 0)
            return ValidateOptionsResult.Fail(
                $"{setting} is empty, which refuses every client registration: leave it unset to allow every " +
                "supported grant type, or name the grant types new clients may request.");

        if (allowed.Any(string.IsNullOrWhiteSpace))
            return ValidateOptionsResult.Fail($"{setting} holds a blank grant type.");

        return ValidateOptionsResult.Success;
    }
}
