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

using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Common.Interfaces;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Options;
using CoreModel = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Maps an encoded authorization response onto the wire DTO and delivers it as an <see cref="IResult"/>: a redirect
/// (query/fragment), a form_post page, an interaction-page redirect, or a no-redirect error. Protocol-level decisions
/// (parameter assembly, iss/scope gating, JARM packing) are made upstream by the core encoder.
/// </summary>
public class AuthorizationResultFormatter(
    IOptions<OidcOptions> options,
    IAuthorizationRequestStorage authorizationRequestStorage,
    ISessionManagementService sessionManagementService,
    IParametersProvider parametersProvider,
    IHttpContextAccessor httpContextAccessor) : IAuthorizationResultFormatter
{
    /// <inheritdoc />
    public async Task<IResult> FormatResponseAsync(CoreModel.AuthorizationRequest request, AuthorizationResponse response)
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

            // prompt=create: a dedicated registration UI when configured, otherwise the login UI — the original
            // request parameters travel in the redirect so a combined page can still branch on them.
            case RegistrationRequired:
                return await RedirectAsync(
                    options.Value.RegistrationUri ?? options.Value.LoginUri.NotNull(nameof(OidcOptions.LoginUri)),
                    response.Model);

            // JARM (*.jwt): success and error alike deliver the single packed response JWT. Matched first so any
            // JWT-bearing response takes this path.
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

    private IResult Deliver(ClientDeliveredResponse response, CoreModel.AuthorizationResponse dto)
    {
        Uri redirectUri;

        switch (response)
        {
            case SuccessfullyAuthenticated { Model.RedirectUri: { } successUri }:
                redirectUri = successUri;
                break;

            case AuthorizationError { RedirectUri: { } errorUri }:
                redirectUri = errorUri;
                break;

            // An error with no usable redirect URI (e.g. an invalid redirect_uri) is surfaced directly.
            case AuthorizationError { RedirectUri: null, Error: var error, ErrorDescription: var description }:
                return Results.Json(new CoreModel.ErrorResponse(error, description), statusCode: StatusCodes.Status400BadRequest);

            default:
                throw new UnexpectedTypeException(nameof(response), response.GetType());
        }

        IResult result = response.ResponseMode switch
        {
            ResponseModes.FormPost => new FormPostResult(parametersProvider, dto, redirectUri),
            ResponseModes.Query => Results.Redirect(redirectUri.AddToQuery(GetParametersFrom(dto))),
            ResponseModes.Fragment => Results.Redirect(redirectUri.AddToFragment(GetParametersFrom(dto))),
            _ => throw new InvalidOperationException($"Response mode '{response.ResponseMode}' is not supported"),
        };

        // The session_state cookie is set for a successful authentication, keyed on the runtime type so a JARM
        // success (matched by the *.jwt branch above) still receives it.
        if (response is SuccessfullyAuthenticated authenticated &&
            sessionManagementService.Enabled &&
            authenticated.SessionId.HasValue() &&
            authenticated.Model.Scope.Contains(Scopes.OpenId))
        {
            var cookie = sessionManagementService.GetSessionCookie();

            result = result.WithAppendCookie(
                cookie.Name,
                authenticated.SessionId,
                cookie.Options.ConvertOptions());
        }

        return result;
    }

    private static CoreModel.AuthorizationResponse MapSuccess(SuccessfullyAuthenticated success) => new()
    {
        State = success.Model.State,
        Issuer = success.Issuer,
        Scope = success.Scope,
        Code = success.Code,
        TokenType = success.TokenType,
        // RFC 6749 §4.2.2: expires_in is RECOMMENDED whenever an access token is delivered from the authorization
        // endpoint; derived from the issued token's own iat/exp so the advertised lifetime matches the token.
        ExpiresIn = success.AccessToken is { Token.Payload: { ExpiresAt: { } expiresAt, IssuedAt: { } issuedAt } }
            ? expiresAt - issuedAt
            : null,
        AccessToken = success.AccessToken?.EncodedJwt,
        IdToken = success.IdToken?.EncodedJwt,
        SessionState = success.SessionState,
    };

    private static CoreModel.AuthorizationResponse MapError(AuthorizationError error) => new()
    {
        State = error.Model.State,
        Issuer = error.Issuer,
        Error = error.Error,
        ErrorDescription = error.ErrorDescription,
        ErrorUri = error.ErrorUri,
    };

    private (string name, string? value)[] GetParametersFrom(CoreModel.AuthorizationResponse response)
        => parametersProvider.GetParameters(response).ToArray();

    private async Task<IResult> RedirectAsync(Uri uri, CoreModel.AuthorizationRequest request)
    {
        var stored = await authorizationRequestStorage.StoreAsync(request, options.Value.LoginSessionExpiresIn);
        var resolved = ResolveContent(uri);
        var target = resolved.AddToQuery([(options.Value.RequestUriParameterName, stored.RequestUri.OriginalString)]);
        return Results.Redirect(target);
    }

    /// <summary>
    /// Resolves a relative interaction URI to an absolute one against the current request's application base URL,
    /// honoring the <c>~/</c> application-root prefix (the Minimal API counterpart of the MVC <c>IUriResolver</c>).
    /// </summary>
    private Uri ResolveContent(Uri uri)
    {
        if (uri.IsAbsoluteUri)
            return uri;

        var request = httpContextAccessor.HttpContext.NotNull(nameof(HttpContext)).Request;
        var appUrl = request.GetAppUrl();
        var path = uri.OriginalString;

        return path.StartsWith("~/")
            ? new Uri(appUrl + path[1..], UriKind.Absolute)
            : new Uri(new Uri(appUrl, UriKind.Absolute), path);
    }
}
