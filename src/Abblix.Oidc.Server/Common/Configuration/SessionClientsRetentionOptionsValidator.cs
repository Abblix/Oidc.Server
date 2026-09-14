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
/// Fails at startup on a retention that would keep no record of which clients signed in to a session.
/// </summary>
/// <remarks>
/// At zero or below a record would expire as it is written, so no logout could read it. A value merely shorter
/// than the host's sessions cannot be detected here, because the session lifetime is the host's cookie setting.
/// </remarks>
public sealed class SessionClientsRetentionOptionsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        if (options.SessionClientsRetention <= TimeSpan.Zero)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(options.SessionClientsRetention)} is {options.SessionClientsRetention}, so the record of " +
                "the clients in a session would expire as it is written and no logout would notify any client. " +
                "Set it to at least the longest a session can last.");
        }

        return ValidateOptionsResult.Success;
    }
}
