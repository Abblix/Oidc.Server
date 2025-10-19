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
/// Validates the requested expiry time for a backchannel authentication request.
/// Ensures that the requested expiry is within the allowed range and assigns a valid expiry time to the context.
/// </summary>
public class RequestedExpiryValidator: IBackChannelAuthenticationContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="RequestedExpiryValidator"/> class.
    /// </summary>
    /// <param name="options">
    /// The options containing the default and maximum expiry settings for backchannel authentication.</param>
    public RequestedExpiryValidator(IOptionsSnapshot<OidcOptions> options)
    {
        _options = options;
    }

    private readonly IOptionsSnapshot<OidcOptions> _options;

    /// <summary>
    /// Asynchronously validates the expiry time for the backchannel authentication request.
    /// Ensures that the requested expiry is within the allowed range and assigns an appropriate expiry to the context.
    /// </summary>
    /// <param name="context">
    /// The validation context containing the backchannel authentication request and its parameters.</param>
    /// <returns>A task representing the asynchronous operation, returning an error if validation fails,
    /// or null if validation succeeds.</returns>
    public Task<RequestError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
        => Task.FromResult(Validate(context));

    /// <summary>
    /// Synchronously validates the expiry time for the backchannel authentication request.
    /// </summary>
    /// <param name="context">
    /// The validation context containing the backchannel authentication request and its parameters.</param>
    /// <returns>
    /// An error if the requested expiry exceeds the allowed maximum, or null if validation is successful.</returns>
    private RequestError? Validate(BackChannelAuthenticationValidationContext context)
    {
        if (!context.Request.RequestedExpiry.HasValue)
        {
            context.ExpiresIn = _options.Value.BackChannelAuthentication.DefaultExpiry;
        }
        else if (context.Request.RequestedExpiry.Value <= _options.Value.BackChannelAuthentication.MaximumExpiry)
        {
            context.ExpiresIn = context.Request.RequestedExpiry.Value;
        }
        else
        {
            return new RequestError(
                ErrorCodes.InvalidRequest,
                "Requested expiry is too long");
        }

        return null;
    }
}
