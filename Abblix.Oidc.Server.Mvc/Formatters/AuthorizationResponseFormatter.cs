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
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Binders;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using CoreModel = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Handles the formatting of authorization responses in compliance with OpenID Connect and OAuth 2.0 protocols.
/// Protocol-level decisions (parameter assembly, iss/scope gating, JARM packing) are made upstream by the core
/// response encoder; this formatter maps the encoded response onto the MVC wire DTO and delivers it to the
/// client's redirect URI via query, fragment or form_post — for both successful and error responses.
/// </summary>
/// <param name="options">Provides the configured interaction URIs (login, consent, …) and request-uri
/// parameter name used when redirecting the user agent to the authorization server's own UI.</param>
/// <param name="authorizationRequestStorage">Stores the pending authorization request when redirecting to an
/// interaction page, returning the request_uri that links back to it.</param>
/// <param name="sessionManagementService">Supplies the OIDC Session Management cookie appended to a successful
/// authentication response.</param>
/// <param name="uriResolver">Resolves relative interaction URIs to absolute ones for redirection.</param>
/// <param name="parametersProvider">Flattens the MVC wire DTO into name/value pairs for delivery.</param>
public class AuthorizationResponseFormatter(
    IOptions<OidcOptions> options,
    IAuthorizationRequestStorage authorizationRequestStorage,
    ISessionManagementService sessionManagementService,
    IUriResolver uriResolver,
    IParametersProvider parametersProvider) : IAuthorizationResponseFormatter
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
        CoreModel.AuthorizationRequest request,
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

            // prompt=create (Initiating User Registration via OpenID Connect 1.0): a dedicated
            // registration UI when the host configured one, otherwise the login UI — the original
            // request parameters (including prompt=create) travel in the redirect, so a combined
            // login/registration page can still branch on them.
            case RegistrationRequired:
                return await RedirectAsync(
                    options.Value.RegistrationUri
                        ?? options.Value.LoginUri.NotNull(nameof(OidcOptions.LoginUri)),
                    response.Model);

            // iss/scope gating and JARM packing are applied upstream by the core response encoder (run from
            // the handler); here we only map the encoded response onto the MVC wire DTO and deliver it.

            // JARM (*.jwt): success and error alike deliver an identical wire shape — the single `response`
            // JWT packed by the encoder. Matched before the plaintext branches so any JWT-bearing response
            // (of either type) takes this path.
            case ClientDeliveredResponse { ResponseJwt: { } responseJwt } jarm:
                return Deliver(jarm, new CoreModel.AuthorizationResponse { Response = responseJwt });

            case SuccessfullyAuthenticated success:
                return Deliver(success, MapSuccess(success));

            case AuthorizationError error:
                return Deliver(error, MapError(error));

            default:
                throw new UnexpectedTypeException(nameof(response), response.GetType());
        }
    }

    /// <summary>
    /// Delivers an encoded client-bound response (success or error) to its redirect URI through the resolved
    /// response mode, appending the OIDC Session Management cookie for successful authentications. An error
    /// with no redirect URI (e.g. an invalid redirect_uri) is surfaced directly as a bad request.
    /// </summary>
    private ActionResult Deliver(ClientDeliveredResponse response, CoreModel.AuthorizationResponse dto)
    {
        Uri redirectUri;

        switch (response)
        {
            case SuccessfullyAuthenticated { Model.RedirectUri: {} successUri }:
                redirectUri = successUri;
                break;

            case AuthorizationError { RedirectUri: {} errorUri }:
                redirectUri = errorUri;
                break;

            case AuthorizationError { RedirectUri: null, Error: var error, ErrorDescription: var description }:
                return new BadRequestObjectResult(new CoreModel.ErrorResponse(error, description));

            default:
                throw new UnexpectedTypeException(nameof(response), response.GetType());
        }

        ActionResult actionResult = response.ResponseMode switch
        {
            ResponseModes.FormPost => new OkObjectResult(dto)
            {
                Formatters = { new AutoPostFormatter(parametersProvider, redirectUri) },
            },

            ResponseModes.Query => new RedirectResult(redirectUri.AddToQuery(GetParametersFrom(dto))),
            ResponseModes.Fragment => new RedirectResult(redirectUri.AddToFragment(GetParametersFrom(dto))),

            _ => throw new InvalidOperationException($"Response mode '{response.ResponseMode}' is not supported"),
        };

        // The session_state cookie is set for a successful authentication independent of JARM/plaintext —
        // keyed on the runtime type, so a JARM success (matched by the *.jwt branch above) still receives it.
        if (response is SuccessfullyAuthenticated authenticated &&
            sessionManagementService.Enabled &&
            authenticated.SessionId.HasValue() &&
            authenticated.Model.Scope.Contains(Scopes.OpenId))
        {
            var cookie = sessionManagementService.GetSessionCookie();

            actionResult = actionResult.WithAppendCookie(
                cookie.Name,
                authenticated.SessionId,
                cookie.Options.ConvertOptions());
        }

        return actionResult;
    }

    /// <summary>
    /// Maps a plaintext successful authentication onto the MVC wire DTO. JARM responses are mapped by the
    /// caller to the single <c>response</c> JWT parameter instead.
    /// </summary>
    private static CoreModel.AuthorizationResponse MapSuccess(SuccessfullyAuthenticated success) => new()
    {
        State = success.Model.State,
        Issuer = success.Issuer,
        Scope = success.Scope,
        Code = success.Code,
        TokenType = success.TokenType,
        AccessToken = success.AccessToken?.EncodedJwt,
        // RFC 6749 §4.2.2: expires_in is RECOMMENDED whenever an access token is delivered from
        // the authorization endpoint (implicit/hybrid). Derived from the issued token's own
        // iat/exp pair, so the advertised lifetime always matches the token itself.
        ExpiresIn = success.AccessToken is { Token.Payload: { ExpiresAt: { } expiresAt, IssuedAt: { } issuedAt } }
            ? expiresAt - issuedAt
            : null,
        IdToken = success.IdToken?.EncodedJwt,
        SessionState = success.SessionState,
    };

    /// <summary>
    /// Maps a plaintext authorization error onto the MVC wire DTO.
    /// </summary>
    private static CoreModel.AuthorizationResponse MapError(AuthorizationError error) => new()
    {
        State = error.Model.State,
        Issuer = error.Issuer,
        Error = error.Error,
        ErrorDescription = error.ErrorDescription,
        ErrorUri = error.ErrorUri,
    };

    /// <summary>
    /// Extracts and formats response parameters from the MVC wire DTO.
    /// </summary>
    private (string name, string? value)[] GetParametersFrom(CoreModel.AuthorizationResponse response)
        => parametersProvider.GetParameters(response).ToArray();

    /// <summary>
    /// Helper method to redirect the user agent to a specified URI while attaching an authorization request.
    /// </summary>
    /// <param name="uri">The base URI to redirect to.</param>
    /// <param name="request">The authorization request to attach to the URI as a query parameter.</param>
    /// <returns>A task that returns a redirect action result.</returns>
    private async Task<ActionResult> RedirectAsync(Uri uri, CoreModel.AuthorizationRequest request)
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
