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

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.UriValidation;
using Microsoft.Extensions.Logging;



namespace Abblix.Oidc.Server.Endpoints.Authorization.Validation;

/// <summary>
/// Validates the redirect URI specified in the authorization request.
/// This class checks whether the provided redirect URI matches one of the client's registered redirect URIs,
/// as part of the authorization validation process. It is essential for ensuring that redirections
/// only occur to pre-approved locations, enhancing security in the OAuth 2.0 flow.
/// </summary>
/// <param name="logger">The logger to be used for logging validation process and outcomes.</param>
public class RedirectUriValidator(ILogger<RedirectUriValidator> logger) : SyncAuthorizationContextValidatorBase
{
    /// <summary>
    /// Validates the redirect URI specified in the authorization request against the registered redirect URIs
    /// for the client. Ensures that the redirect URI is one of the pre-approved URIs for the client making the request.
    /// This validation is crucial for preventing unauthorized redirections in the OAuth 2.0 authorization flow.
    /// </summary>
    /// <param name="context">The validation context containing client information and the request details.</param>
    /// <returns>
    /// An <see cref="AuthorizationRequestValidationError"/> if the redirect URI is not valid for the specified client,
    /// or null if the redirect URI is valid.
    /// </returns>
    protected override AuthorizationRequestValidationError? Validate(AuthorizationValidationContext context)
    {
        var uriValidator = UriValidatorFactory.Create(context.ClientInfo.RedirectUris);

        var redirectUri = context.Request.RedirectUri;
        if (redirectUri == null || !uriValidator.IsValid(redirectUri))
        {
            logger.LogWarning("The redirect URI {RedirectUri} is invalid for client with id {ClientId}",
                redirectUri,
                context.ClientInfo.ClientId);

            return context.InvalidRequest("The redirect URI is not valid for specified client");
        }

        context.ValidRedirectUri = redirectUri;

        return null;
    }
}
