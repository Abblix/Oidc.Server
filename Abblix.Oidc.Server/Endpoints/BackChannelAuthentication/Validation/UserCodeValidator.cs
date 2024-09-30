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

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Interfaces;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Endpoints.BackChannelAuthentication.Validation;

/// <summary>
/// Validates the presence of a UserCode in backchannel authentication requests, based on the client
/// and provider configuration. This validator ensures that if the client or provider requires the
/// UserCode parameter for backchannel authentication, it is included in the request.
/// </summary>
public class UserCodeValidator : IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="UserCodeValidator"/> class.
    /// The constructor accepts OIDC options, allowing the validator to access the configuration
    /// settings that determine if the UserCode parameter is required.
    /// </summary>
    /// <param name="options">
    /// The OIDC options used to configure the behavior of the backchannel authentication process.</param>
    public UserCodeValidator(IOptions<OidcOptions> options)
    {
        _options = options;
    }

    private readonly IOptions<OidcOptions> _options;

    /// <summary>
    /// Asynchronously validates the UserCode parameter in the context of a backchannel authentication request.
    /// If the UserCode is required but not present, the method returns an error. Otherwise, it returns null.
    /// </summary>
    /// <param name="context">
    /// The validation context containing the authentication request and client information.</param>
    /// <returns>
    /// A task that represents the asynchronous operation, returning an error if validation fails,
    /// or null if successful.</returns>
    public Task<BackChannelAuthenticationValidationError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Performs the actual validation of the UserCode parameter. Checks whether the provider and client require
    /// the UserCode parameter for the current request and ensures that it is present in the request.
    /// </summary>
    /// <param name="context">The validation context containing the backchannel authentication request details.</param>
    /// <returns>
    /// A <see cref="BackChannelAuthenticationValidationError"/> if the UserCode is missing when required,
    /// or null otherwise.</returns>
    private BackChannelAuthenticationValidationError? Validate(BackChannelAuthenticationValidationContext context)
    {
        // Check if the provider and client both require the UserCode parameter.
        var requireUserCode = _options.Value.BackChannelAuthentication.UserCodeParameterSupported &&
                              context.ClientInfo.BackChannelUserCodeParameter;

        // Return an error if UserCode is required but missing from the request.
        if (requireUserCode && string.IsNullOrEmpty(context.Request.UserCode))
        {
            return new BackChannelAuthenticationValidationError(
                ErrorCodes.MissingUserCode,
                "The UserCode parameter is missing.");
        }

        // If no errors, return null (indicating a successful validation).
        return null;
    }
}
