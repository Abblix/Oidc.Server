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

public class UserCodeValidator: IBackChannelAuthenticationContextValidator
{
    public UserCodeValidator(IOptions<OidcOptions> options)
    {
        _options = options;
    }

    private readonly IOptions<OidcOptions> _options;

    public Task<BackChannelAuthenticationValidationError?> ValidateAsync(BackChannelAuthenticationValidationContext context)
        => Task.FromResult(Validate(context));

    private BackChannelAuthenticationValidationError? Validate(BackChannelAuthenticationValidationContext context)
    {
        var requireUserCode = _options.Value.BackChannelAuthentication.UserCodeParameterSupported &&
                                    context.ClientInfo.BackChannelUserCodeParameter;

        if (requireUserCode && string.IsNullOrEmpty(context.Request.UserCode))
        {
            return new BackChannelAuthenticationValidationError(
                ErrorCodes.MissingUserCode,
                "The UserCode parameter is missing.");
        }

        return null;
    }
}
