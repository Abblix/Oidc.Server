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
/// Refuses at startup the revoked initial access token subjects listed in the server options, which the server no
/// longer reads.
/// </summary>
/// <remarks>
/// The subjects are each tenant's now. Left in the server options they would be ignored, and every token they revoke
/// would register clients again with nothing saying so.
/// </remarks>
public sealed class RevokedInitialAccessTokenSubjectsValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        // Reading the setting is this validator's whole purpose, so its obsolescence is not a warning here
#pragma warning disable CS0618
        var listed = options.RevokedInitialAccessTokenSubjects.Count;
#pragma warning restore CS0618
        if (listed == 0)
            return ValidateOptionsResult.Success;

        return ValidateOptionsResult.Fail(
            $"The server options list {listed} revoked initial access token subject(s), which the server no longer " +
            "reads. Declare them on the tenant that issued the tokens, as " +
            "TenantDefinition.RevokedInitialAccessTokenSubjects.");
    }
}
