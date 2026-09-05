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
/// Validates the presence of a UserCode in backchannel authentication requests, based on the client
/// and provider configuration. This validator ensures that if the client or provider requires the
/// UserCode parameter for backchannel authentication, it is included in the request.
/// </summary>
/// <remarks>
/// This validator checks <em>presence</em> only. Verifying the code's <em>value</em> against the
/// user's actual code is the host's responsibility and happens during the device interaction - see
/// the security contract on
/// <see cref="Features.BackChannelAuthentication.Interfaces.IUserDeviceAuthenticationHandler"/>.
/// </remarks>
/// <param name="options">
/// The OIDC options used to configure the behavior of the backchannel authentication process.</param>
public class UserCodeValidator(IOptions<OidcOptions> options) : IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Asynchronously validates the UserCode parameter in the context of a backchannel authentication request.
    /// If the UserCode is required but not present, the method returns an error. Otherwise, it returns null.
    /// </summary>
    /// <param name="context">
    /// The validation context containing the authentication request and client information.</param>
    /// <returns>
    /// A task that returns an error if validation fails,
    /// or null if successful.</returns>
    public Task<OidcError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Performs the actual validation of the UserCode parameter. Checks whether the provider and client require
    /// the UserCode parameter for the current request and ensures that it is present in the request.
    /// </summary>
    /// <param name="context">The validation context containing the backchannel authentication request details.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if the UserCode is missing when required,
    /// or null otherwise.</returns>
    private OidcError? Validate(BackChannelAuthenticationValidationContext context)
    {
        var requireUserCode = options.Value.BackChannelAuthentication.UserCodeParameterSupported &&
                              context.ClientInfo.BackChannelUserCodeParameter;

        if (requireUserCode && string.IsNullOrEmpty(context.Request.UserCode))
        {
            return new OidcError(
                ErrorCodes.MissingUserCode,
                "The UserCode parameter is missing.");
        }

        return null;
    }
}
