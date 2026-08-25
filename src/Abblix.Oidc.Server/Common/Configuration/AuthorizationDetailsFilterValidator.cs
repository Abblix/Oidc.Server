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
/// Refuses at startup a <see cref="OidcOptions.FilterAuthorizationDetailsByLocation"/> that can only ever
/// delete data.
/// </summary>
/// <remarks>
/// The same contradiction <see cref="DefaultResourceIndicatorValidator"/> exists for, and invisible in the
/// same way: the token still issues, the claim is simply not in it, and whoever needed it reports a missing
/// permission from somewhere else, later.
/// </remarks>
public sealed class AuthorizationDetailsFilterValidator : IValidateOptions<OidcOptions>
{
    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, OidcOptions options)
    {
        if (!options.FilterAuthorizationDetailsByLocation || options.Resources is { Length: > 0 })
            return ValidateOptionsResult.Success;

        // With no resource registered, nothing can put one in the audience. A request naming a resource is
        // refused as invalid_target before it gets that far, and DefaultResourceIndicator cannot be set,
        // because the validator beside this one requires it to name a registered resource. So the audience
        // is the issuer on every token, no locations value can match it, and the filter deletes every
        // located entry from everything this server issues - not sometimes, and not for a namespace
        // mismatch a host could reason about, but always.
        return ValidateOptionsResult.Fail(
            $"{nameof(OidcOptions.FilterAuthorizationDetailsByLocation)} is on while no " +
            $"{nameof(OidcOptions.Resources)} are configured, so every access token's audience is the " +
            $"issuer and every authorization_details entry carrying locations would be dropped from every " +
            $"token. Register the resources whose identifiers the locations name, or turn the filter off.");
    }
}
