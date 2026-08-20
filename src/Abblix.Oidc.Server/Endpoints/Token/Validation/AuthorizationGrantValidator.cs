// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Endpoints.Token.Grants;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Validates the authorization grant in the context of a token request, ensuring that the request is authorized
/// and that the associated redirect URI matches the one used during the initial authorization request
/// </summary>
/// <remarks>
/// This validator interacts with the <see cref="IAuthorizationGrantHandler"/> to perform the necessary checks
/// on the authorization grant. It ensures that the token request is made for an authorized grant and verifies
/// the consistency of the redirect URI. If the grant is valid and authorized, it updates the validation context
/// </remarks>
/// <param name="grantHandler">The handler responsible for authorizing the grant.</param>
public class AuthorizationGrantValidator(IAuthorizationGrantHandler grantHandler): ITokenContextValidator
{
    /// <summary>
    /// Asynchronously validates the authorization grant in the token request context. This method checks if the grant
    /// is valid and authorized for the client making the request. It also ensures that the redirect URI used in the
    /// token request matches the one used during the initial authorization request.
    /// </summary>
    /// <param name="context">The validation context containing the token request and client information.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if the authorization grant is invalid,
    /// including an error code and description;
    /// otherwise, null indicating that the grant is valid and the context has been updated.
    /// </returns>
    /// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
    public async Task<OidcError?> ValidateAsync(TokenValidationContext context, CancellationToken cancellationToken)
    {
        // Ensure the client is authorized to use the requested grant type
        if (!context.ClientInfo.EffectiveGrantTypes.Contains(context.Request.GrantType))
        {
            return new OidcError(
                ErrorCodes.UnauthorizedClient,
                "The grant type is not allowed for this client");
        }

        var result = await grantHandler.AuthorizeAsync(context.Request, context.ClientInfo, cancellationToken);

        if (result.TryGetFailure(out var error))
        {
            return error;
        }

        var grant = result.GetSuccess();

        // Ensure that the redirect URI used matches the original authorization request
        // to prevent redirection attacks
        if (grant.Context.RedirectUri != context.Request.RedirectUri)
        {
            return new OidcError(
                ErrorCodes.InvalidGrant,
                "The redirect Uri value does not match to the value used before");
        }

        // Accept the request if the grant is valid, and securely store it in the validation context
        // for further processing
        context.AuthorizedGrant = grant;
        return null;
    }
}
