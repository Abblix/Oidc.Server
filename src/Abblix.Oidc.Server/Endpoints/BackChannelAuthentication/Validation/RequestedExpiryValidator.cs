// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates the requested expiry time for a backchannel authentication request.
/// Ensures that the requested expiry is within the allowed range and assigns a valid expiry time to the context.
/// </summary>
/// <param name="options">
/// The options containing the default and maximum expiry settings for backchannel authentication.</param>
public class RequestedExpiryValidator(IOptionsMonitor<OidcOptions> options) : IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Asynchronously validates the expiry time for the backchannel authentication request.
    /// Ensures that the requested expiry is within the allowed range and assigns an appropriate expiry to the context.
    /// </summary>
    /// <param name="context">
    /// The validation context containing the backchannel authentication request and its parameters.</param>
    /// <returns>A task representing the asynchronous operation, returning an error if validation fails,
    /// or null if validation succeeds.</returns>
    public Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Synchronously validates the expiry time for the backchannel authentication request.
    /// </summary>
    /// <param name="context">
    /// The validation context containing the backchannel authentication request and its parameters.</param>
    /// <returns>
    /// An error if the requested expiry exceeds the allowed maximum, or null if validation is successful.</returns>
    private OidcError? Validate(BackChannelAuthenticationValidationContext context)
    {
        if (!context.Request.RequestedExpiry.HasValue)
        {
            context.ExpiresIn = options.CurrentValue.BackChannelAuthentication.DefaultExpiry;
        }
        else if (context.Request.RequestedExpiry.Value <= options.CurrentValue.BackChannelAuthentication.MaximumExpiry)
        {
            context.ExpiresIn = context.Request.RequestedExpiry.Value;
        }
        else
        {
            return new OidcError(
                ErrorCodes.InvalidRequest,
                "Requested expiry is too long");
        }

        return null;
    }
}
