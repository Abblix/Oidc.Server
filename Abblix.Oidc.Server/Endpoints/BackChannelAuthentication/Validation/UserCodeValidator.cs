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
    public Task<AuthError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Performs the actual validation of the UserCode parameter. Checks whether the provider and client require
    /// the UserCode parameter for the current request and ensures that it is present in the request.
    /// </summary>
    /// <param name="context">The validation context containing the backchannel authentication request details.</param>
    /// <returns>
    /// A <see cref="AuthError"/> if the UserCode is missing when required,
    /// or null otherwise.</returns>
    private AuthError? Validate(BackChannelAuthenticationValidationContext context)
    {
        var requireUserCode = options.Value.BackChannelAuthentication.UserCodeParameterSupported &&
                              context.ClientInfo.BackChannelUserCodeParameter;

        if (requireUserCode && string.IsNullOrEmpty(context.Request.UserCode))
        {
            return new AuthError(
                ErrorCodes.MissingUserCode,
                "The UserCode parameter is missing.");
        }

        return null;
    }
}
