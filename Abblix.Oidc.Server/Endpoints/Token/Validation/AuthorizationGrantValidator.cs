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

using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Token.Grants;
using Abblix.Oidc.Server.Endpoints.Token.Interfaces;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

public class AuthorizationGrantValidator: ITokenContextValidator
{
    public AuthorizationGrantValidator(IAuthorizationGrantHandler grantHandler)
    {
        _grantHandler = grantHandler;
    }

    private readonly IAuthorizationGrantHandler _grantHandler;

    public async Task<TokenRequestError?> ValidateAsync(TokenValidationContext context)
    {
        var result = await _grantHandler.AuthorizeAsync(context.Request, context.ClientInfo);
        switch (result)
        {
            case InvalidGrantResult { Error: var error, ErrorDescription: var description }:
                return new TokenRequestError(error, description);

            case AuthorizedGrant { Context.RedirectUri: var redirectUri }
                when redirectUri != context.Request.RedirectUri:
                return new TokenRequestError(
                    ErrorCodes.InvalidGrant,
                    "The redirect Uri value does not match to the value used before");

            case AuthorizedGrant grant:
                context.AuthorizedGrant = grant;
                return null;

            default:
                throw new UnexpectedTypeException(nameof(result), result.GetType());
        }
    }
}
