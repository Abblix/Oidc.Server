// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Constants;
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
        var profile = SecurityProfileRequirements.For(context.ClientInfo, tenant.DefaultSecurityProfile);
        var exactHttps = profile.RequireExactHttpsRedirectUris;
        var uriValidator = UriValidatorFactory.CreateForRedirectUris(context.ClientInfo.RedirectUris);

        var redirectUri = context.Request.RedirectUri ?? SoleRegisteredUri(context, profile);

        // A client the host's own store supplies never met the check of the settings, so its redirect URI is held to
        // the schemes its kind of client may use here, once it matched a registered one and is known to be absolute
        if (redirectUri is not { } uri || !Matches(uri) || !IsAllowedFor(context.ClientInfo, uri))
        {
            LogInvalidRedirectUri(redirectUri, context.ClientInfo.ClientId);

            return context.InvalidRequest("The redirect URI is not valid for specified client");
        }

        // The request goes on carrying the URI it is served at, so what follows answers there, and the code it is
        // issued remembers whether the client named it
        if (context.Request.RedirectUri is null)
            context.Request = context.Request with { RedirectUri = uri, ClientNamedNoRedirectUri = true };

        context.ValidRedirectUri = uri;

        return null;

        bool Matches(Uri uri)
            => !(exactHttps && uri is not { IsAbsoluteUri: true, Scheme: "https" }) && uriValidator.IsValid(uri);
    }

    /// <summary>
    /// The redirect URI a request naming none is served at, or null where it has to name one.
    /// </summary>
    /// <remarks>
    /// OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 4.1.1: redirect_uri is "OPTIONAL if only one redirect URI is
    /// registered for this client. REQUIRED if multiple redirect URIs are registered for this client", and section
    /// 2.3.2 repeats it. OpenID Connect Core 1.0 section 3.1.2.1 has it "REQUIRED" in an Authentication Request, so a
    /// request served the openid scope, named or as the client's default, names it; and so does a client held to a
    /// profile requiring it (<see cref="SecurityProfileRequirements.RequireRedirectUriParameter"/>).
    /// </remarks>
    private static Uri? SoleRegisteredUri(AuthorizationValidationContext context, SecurityProfileRequirements profile)
    {
        if (profile.RequireRedirectUriParameter ||
            context.ClientInfo.RedirectUris is not [var sole] ||
            context.ServedScope() is not { } served ||
            served.Contains(Scopes.OpenId, StringComparer.Ordinal))
        {
            return null;
        }

        return sole;
    }

    /// <remarks>
    /// The query is held to OAuth 2.1 (draft-ietf-oauth-v2-1-17) section 2.3 too: it "MUST NOT include any parameters
    /// defined for use in the authorization response", which would reach the client beside the ones added here.
    /// </remarks>
    private static bool IsAllowedFor(ClientInfo client, Uri uri)
        => RedirectUriSchemes.IsAllowed(uri, native: client.ApplicationType == ApplicationTypes.Native) &&
           RedirectUriQuery.ResponseParameterIn(uri) is null;
}
