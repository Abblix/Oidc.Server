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
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Endpoints.Configuration.Interfaces;
using Abblix.Oidc.Server.Features.Issuer;
using Abblix.Oidc.Server.Features.Tokens.Formatters;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Mvc.Binders;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using AuthorizationResponse = Abblix.Oidc.Server.Mvc.Model.AuthorizationResponse;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Handles the formatting of authorization responses in compliance with OpenID Connect and OAuth 2.0 protocols.
/// This formatter is responsible for transforming internal authorization response models into appropriate
/// HTTP responses that can be understood by clients and end-users.
/// </summary>
public class AuthorizationResponseFormatter(
    IOptions<OidcOptions> options,
    IAuthorizationRequestStorage authorizationRequestStorage,
    ISessionManagementService sessionManagementService,
    IUriResolver uriResolver,
    IIssuerProvider issuerProvider,
    IAuthorizationMetadataProvider authorizationMetadata,
    IParametersProvider parametersProvider,
    IAuthorizationResponseEncoder responseEncoder,
    IAuthorizationErrorFormatter errorFormatter) : IAuthorizationResponseFormatter
{
    /// <summary>
    /// Formats an authorization response based on the specified request and response model asynchronously.
    /// It handles various outcomes such as redirections for additional user interactions and successful authentication,
    /// adapting the response according to the OpenID Connect and OAuth 2.0 specifications.
    /// </summary>
    /// <param name="request">The authorization request containing details about the initial request from the client.
    /// </param>
    /// <param name="response">The authorization response model to format.</param>
    /// <returns>A task that returns an <see cref="ActionResult"/>
    /// that can be returned by an ASP.NET Core controller.</returns>
    public async Task<ActionResult> FormatResponseAsync(
        AuthorizationRequest request,
        Endpoints.Authorization.Interfaces.AuthorizationResponse response)
    {
        switch (response)
        {
            case AccountSelectionRequired:
                return await RedirectAsync(
                    options.Value.AccountSelectionUri.NotNull(nameof(OidcOptions.AccountSelectionUri)), response.Model);

            case ConsentRequired:
                return await RedirectAsync(
                    options.Value.ConsentUri.NotNull(nameof(OidcOptions.ConsentUri)), response.Model);

            case InteractionRequired:
                return await RedirectAsync(
                    options.Value.InteractionUri.NotNull(nameof(OidcOptions.InteractionUri)), response.Model);

            case LoginRequired:
                return await RedirectAsync(
                    options.Value.LoginUri.NotNull(nameof(OidcOptions.LoginUri)), response.Model);

            case SuccessfullyAuthenticated { Model.RedirectUri: { } redirectUri } success:

                // Scope is only carried in the authorization response for implicit and hybrid
                // flows (OIDC Core §3.2.2.5 / §3.3.2.5), where the response itself delivers an
                // access_token and/or id_token whose granted scope is asserted up-front. The
                // pure code flow (OAuth 2.0 §4.1.2 / OIDC Core §3.1.2.5) returns only code +
                // state (+ optional iss per RFC 9207); the granted scope is resolved later at
                // the token endpoint. Emitting scope on the code-flow callback is a non-spec
                // extension that OIDF Conformance flags as "unexpected parameters" and FAPI 2.0
                // explicitly disallows in §5.3.1 (response_type=code only). Gate on the
                // implicit/hybrid markers (any token-bearing field) so code-only flows omit it.
                var carriesTokens = success.AccessToken != null || success.IdToken != null;
                var modelResponse = new AuthorizationResponse
                {
                    State = response.Model.State,
                    Issuer = authorizationMetadata.AuthorizationResponseIssParameterSupported ? issuerProvider.GetIssuer() : null,
                    Scope = carriesTokens ? string.Join(' ', response.Model.Scope) : null,
                    Code = success.Code,
                    TokenType = success.TokenType,
                    AccessToken = success.AccessToken?.EncodedJwt,
                    IdToken = success.IdToken?.EncodedJwt,
                    SessionState = success.SessionState,
                };

                // JARM (JWT Secured Authorization Response Mode): when the client requested a *.jwt response
                // mode, pack the response parameters into a signed/encrypted `response` JWT (built by the core
                // encoder) and deliver it via the matching plaintext mode.
                var effectiveResponse = modelResponse;
                var deliveryMode = success.ResponseMode;
                if (ResponseModes.IsJwtMode(success.ResponseMode))
                {
                    var parameters = parametersProvider.GetParameters(modelResponse).ToArray();
                    var jarm = await responseEncoder.EncodeAsync(
                        success.ResponseMode, response.Model.ClientId, carriesTokens, parameters);
                    effectiveResponse = new AuthorizationResponse { Response = jarm.ResponseJwt };
                    deliveryMode = jarm.DeliveryMode;
                }

                var actionResult = await errorFormatter.FormatResponseAsync(effectiveResponse, deliveryMode, redirectUri);

                if (sessionManagementService.Enabled &&
                    success.SessionId.HasValue() &&
                    response.Model.Scope.Contains(Scopes.OpenId))
                {
                    var cookie = sessionManagementService.GetSessionCookie();
                    actionResult = actionResult.WithAppendCookie(
                        cookie.Name,
                        success.SessionId,
                        cookie.Options.ConvertOptions());
                }

                return actionResult;

            case AuthorizationError error:
                return await errorFormatter.FormatResponseAsync(response.Model, error);

            default:
                throw new UnexpectedTypeException(nameof(response), response.GetType());
        }
    }

    /// <summary>
    /// Helper method to redirect the user agent to a specified URI while attaching an authorization request.
    /// </summary>
    /// <param name="uri">The base URI to redirect to.</param>
    /// <param name="request">The authorization request to attach to the URI as a query parameter.</param>
    /// <returns>A task that returns a redirect action result.</returns>
    private async Task<ActionResult> RedirectAsync(Uri uri, AuthorizationRequest request)
    {
        var response = await authorizationRequestStorage.StoreAsync(
            request,
            options.Value.LoginSessionExpiresIn);

        if (!uri.IsAbsoluteUri)
        {
            uri = uriResolver.Content(uri.OriginalString);
        }

        return new RedirectResult(new UriBuilder(uri)
        {
            Query =
            {
                [options.Value.RequestUriParameterName] = response.RequestUri.OriginalString,
            }
        });
    }
}
