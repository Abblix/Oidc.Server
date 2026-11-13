// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.MultiTenancy;
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
public partial class RedirectUriValidator(ILogger<RedirectUriValidator> logger) : SyncAuthorizationContextValidatorBase
{
    /// <summary>
    /// Validates the redirect URI specified in the authorization request against the registered redirect URIs
    /// for the client. Ensures that the redirect URI is one of the pre-approved URIs for the client making the request.
    /// This validation is crucial for preventing unauthorized redirections in the OAuth 2.0 authorization flow.
    /// </summary>
    /// <param name="tenant">The tenant the request is served at.</param>
    /// <param name="context">The validation context containing client information and the request details.</param>
    /// <returns>
    /// An <see cref="AuthorizationRequestValidationError"/> if the redirect URI is not valid for the specified client,
    /// or null if the redirect URI is valid.
    /// </returns>
    protected override AuthorizationRequestValidationError? Validate(TenantDefinition tenant, AuthorizationValidationContext context)
    {
        // FAPI 1.0 Part 1 section 5.2.2: "shall require the value of redirect_uri to exactly match one of the
        // pre-registered redirect URIs" and "shall require redirect URIs to use the https scheme". Refusing http is
        // what leaves no room for the loopback port allowance of RFC 8252 section 7.3, which applies to http alone
        var exactHttps = SecurityProfileRequirements
            .For(context.ClientInfo, tenant.DefaultSecurityProfile)
            .RequireExactHttpsRedirectUris;
        var uriValidator = UriValidatorFactory.CreateForRedirectUris(context.ClientInfo.RedirectUris);

        var redirectUri = context.Request.RedirectUri;
        if (redirectUri == null ||
            (exactHttps && redirectUri is not { IsAbsoluteUri: true, Scheme: "https" }) ||
            !uriValidator.IsValid(redirectUri))
        {
            LogInvalidRedirectUri(redirectUri, context.ClientInfo.ClientId);

            return context.InvalidRequest("The redirect URI is not valid for specified client");
        }

        context.ValidRedirectUri = redirectUri;

        return null;
    }
}
