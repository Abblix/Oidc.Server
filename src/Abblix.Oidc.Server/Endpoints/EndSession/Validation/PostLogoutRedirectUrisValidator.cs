// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.UriValidation;
using Microsoft.Extensions.Logging;
using static Abblix.Oidc.Server.Model.EndSessionRequest;

namespace Abblix.Oidc.Server.Endpoints.EndSession.Validation;

/// <summary>
/// Verifies that the request's <c>post_logout_redirect_uri</c> is one of the URIs the
/// resolved client previously registered (OpenID Connect RP-Initiated Logout 1.0 section 2).
/// A request without <c>post_logout_redirect_uri</c> is allowed. One that carries it but names no client, by
/// <c>client_id</c> or <c>id_token_hint</c>, has nothing confirming the address, and section 3 rules out redirecting
/// there; the logout itself is still allowed, so the address and its <c>state</c> are dropped from the request
/// passed on rather than the request refused.
/// </summary>
public partial class PostLogoutRedirectUrisValidator(ILogger<PostLogoutRedirectUrisValidator> logger) : IEndSessionContextValidator
{
    /// <inheritdoc />
    public Task<OidcError?> ValidateAsync(EndSessionValidationContext context)
        => Task.FromResult(Validate(context));

    private OidcError? Validate(EndSessionValidationContext context)
    {
        var request = context.Request;

        var redirectUri = request.PostLogoutRedirectUri;
        if (redirectUri == null)
            return null;

        // OpenID Connect RP-Initiated Logout 1.0 section 3: with neither id_token_hint nor client_id the OP "MUST NOT
        // perform post-logout redirection", while the logout itself still goes ahead after the end user confirms it
        if (context.ClientInfo == null)
        {
            LogRedirectWithoutClientIgnored(redirectUri);
            context.Request = request with { PostLogoutRedirectUri = null, State = null };
            return null;
        }

        var uriValidator = UriValidatorFactory.Create(context.ClientInfo.PostLogoutRedirectUris);
        if (uriValidator.IsValid(redirectUri))
            return null;

        LogInvalidPostLogoutRedirectUri(redirectUri, context.ClientInfo.ClientId);

        return new OidcError(
            ErrorCodes.InvalidRequest,
            "The post-logout redirect URI is not valid for specified client");
    }
}
