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
/// resolved client previously registered (OpenID Connect RP-Initiated Logout 1.0 §2).
/// A request without <c>post_logout_redirect_uri</c> is allowed; if one is present but
/// the client cannot be resolved from <c>client_id</c> or <c>id_token_hint</c>, the
/// redirect URI cannot be safely validated and the request is rejected.
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

        if (context.ClientInfo == null)
        {
             return new OidcError(
                 ErrorCodes.UnauthorizedClient,
                 $"Unable to determine a client from {Parameters.ClientId} or {Parameters.IdTokenHint}, but it is necessary to validate {Parameters.PostLogoutRedirectUri} value");
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
