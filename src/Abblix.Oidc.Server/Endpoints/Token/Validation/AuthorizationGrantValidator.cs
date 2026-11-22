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
using Abblix.Oidc.Server.Features.MultiTenancy;

namespace Abblix.Oidc.Server.Endpoints.Token.Validation;

/// <summary>
/// Validates the authorization grant in the context of a token request, ensuring that the client may use the grant
/// type and that the grant's handler authorizes the request
/// </summary>
/// <remarks>
/// This validator interacts with the <see cref="IAuthorizationGrantHandler"/> to perform the necessary checks
/// on the authorization grant. The checks a grant type owns, such as the redirect URI of the authorization code
/// grant, live in its handler. If the grant is valid and authorized, it updates the validation context
/// </remarks>
/// <param name="grantHandler">The handler responsible for authorizing the grant.</param>
public class AuthorizationGrantValidator(IAuthorizationGrantHandler grantHandler): ITokenContextValidator
{
    /// <summary>
    /// Asynchronously validates the authorization grant in the token request context. This method checks if the grant
    /// is valid and authorized for the client making the request.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="context">The validation context containing the token request and client information.</param>
    /// <returns>
    /// A <see cref="OidcError"/> if the authorization grant is invalid,
    /// including an error code and description;
    /// otherwise, null indicating that the grant is valid and the context has been updated.
    /// </returns>
    /// <param name="cancellationToken">Abandons the operation when the caller stops waiting.</param>
    public async Task<OidcError?> ValidateAsync(TenantDefinition tenant, TokenValidationContext context, CancellationToken cancellationToken)
    {
        // Ensure the client is authorized to use the requested grant type
        if (!context.ClientInfo.MayUseGrantType(context.Request.GrantType))
        {
            return new OidcError(
                ErrorCodes.UnauthorizedClient,
                "The grant type is not allowed for this client");
        }

        // A grant starting from the client alone builds its context from the request's scope, so it is handed the
        // request with the scope it is served with
        var result = await grantHandler.AuthorizeAsync(
            tenant,
            context.Request with { Scope = TokenRequestScope.ServedFor(context) ?? [] },
            context.ClientInfo,
            cancellationToken);

        if (result.TryGetFailure(out var error))
        {
            return error;
        }

        // Accept the request if the grant is valid, and securely store it in the validation context
        // for further processing
        context.AuthorizedGrant = result.GetSuccess();
        return null;
    }
}
