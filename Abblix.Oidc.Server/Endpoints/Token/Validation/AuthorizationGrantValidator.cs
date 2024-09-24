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

/// <summary>
/// Validates the authorization grant in the context of a token request, ensuring that the request is authorized
/// and that the associated redirect URI matches the one used during the initial authorization request.
/// </summary>
/// <remarks>
/// This validator interacts with the <see cref="IAuthorizationGrantHandler"/> to perform the necessary checks
/// on the authorization grant. It ensures that the token request is made for an authorized grant and verifies
/// the consistency of the redirect URI. If the grant is valid and authorized, it updates the validation context.
/// </remarks>
public class AuthorizationGrantValidator: ITokenContextValidator
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationGrantValidator"/> class with
    /// the specified grant handler.
    /// </summary>
    /// <param name="grantHandler">The handler responsible for authorizing the grant.</param>
    public AuthorizationGrantValidator(IAuthorizationGrantHandler grantHandler)
    {
        _grantHandler = grantHandler;
    }

    private readonly IAuthorizationGrantHandler _grantHandler;

    /// <summary>
    /// Asynchronously validates the authorization grant in the token request context. This method checks if the grant
    /// is valid and authorized for the client making the request. It also ensures that the redirect URI used in the
    /// token request matches the one used during the initial authorization request.
    /// </summary>
    /// <param name="context">The validation context containing the token request and client information.</param>
    /// <returns>
    /// A <see cref="TokenRequestError"/> if the authorization grant is invalid,
    /// including an error code and description;
    /// otherwise, null indicating that the grant is valid and the context has been updated.
    /// </returns>
    public async Task<TokenRequestError?> ValidateAsync(TokenValidationContext context)
    {
        if (!context.ClientInfo.AllowedGrantTypes.Contains(context.Request.GrantType))
        {
            return new TokenRequestError(
                ErrorCodes.UnauthorizedClient,
                "The grant type is not allowed for this client");
        }

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
