// Abblix OpenID Connect Server Library
// Copyright (c) 2024 by Abblix LLP
// 
// This software is provided 'as-is', without any express or implied warranty. In no
// event will the authors be held liable for any damages arising from the use of this
// software.
// 
// Permitted Use: This software is open for use and extension by non-profit,
// educational and community projects under the condition that it remains unmodified
// and used in its entirety through official Nuget packages. Any unauthorized
// modification, forking of the whole repository, or altering individual files is
// strictly prohibited to ensure development occurs solely within the official Abblix LLP
// repository.
// 
// Prohibited Actions: Redistribution, modification, incorporation of this software or
// any part thereof into other products, and creation of derivative works are not
// permitted without obtaining a commercial license from Abblix LLP.
// 
// Commercial Use: A separate license is required for commercial use, including
// functionalities extended beyond the original software. For information on obtaining
// a commercial license, please contact Abblix LLP.
// 
// Enforcement: Unauthorized redistribution, modification, or use of this software in
// other projects or products is strictly prohibited without prior written permission
// from the copyright holder. Violations may be subject to legal action.
// 
// For more information, please refer to the license agreement located at:
// https://github.com/Abblix/Oidc.Server/blob/master/README.md

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Binders;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Extensions;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using AuthorizationResponse = Abblix.Oidc.Server.Mvc.Model.AuthorizationResponse;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Handles the formatting of authorization responses in compliance with OpenID Connect and OAuth 2.0 protocols.
/// This formatter is responsible for transforming internal authorization response models into appropriate
/// HTTP responses that can be understood by clients and end-users.
/// </summary>
internal class AuthorizationResponseFormatter : AuthorizationErrorFormatter, IAuthorizationResponseFormatter
{
    /// <summary>
    /// Initializes a new instance of the <see cref="AuthorizationResponseFormatter"/> class, setting up essential
    /// services and configuration options needed to format authorization responses.
    /// </summary>
    /// <param name="options">The configuration options for OpenID Connect.</param>
    /// <param name="authorizationRequestStorage">
    /// The storage service for managing and retrieving authorization requests.</param>
    /// <param name="parametersProvider">
    /// The provider for retrieving additional parameters needed during the formatting process.</param>
    /// <param name="sessionManagementService">
    /// The service responsible for managing user sessions within the authorization process.</param>
    /// <param name="httpContextAccessor">
    /// Accessor to obtain the current HTTP context, facilitating access to request and response objects.</param>

    public AuthorizationResponseFormatter(
        IOptions<OidcOptions> options,
        IAuthorizationRequestStorage authorizationRequestStorage,
        IParametersProvider parametersProvider,
        ISessionManagementService sessionManagementService,
        IHttpContextAccessor httpContextAccessor)
        : base(parametersProvider)
    {
        _options = options;
        _authorizationRequestStorage = authorizationRequestStorage;
        _sessionManagementService = sessionManagementService;
        _httpContextAccessor = httpContextAccessor;
    }

    private readonly IAuthorizationRequestStorage _authorizationRequestStorage;
    private readonly ISessionManagementService _sessionManagementService;
    private readonly IHttpContextAccessor _httpContextAccessor;
    private readonly IOptions<OidcOptions> _options;

    /// <summary>
    /// Formats an authorization response based on the specified request and response model asynchronously.
    /// It handles various outcomes such as redirections for additional user interactions and successful authentication,
    /// adapting the response according to the OpenID Connect and OAuth 2.0 specifications.
    /// </summary>
    /// <param name="request">The authorization request containing details about the initial request from the client.
    /// </param>
    /// <param name="response">The authorization response model to format.</param>
    /// <returns>A task that represents the asynchronous operation and results in an <see cref="ActionResult"/>
    /// that can be returned by an ASP.NET Core controller.</returns>
    public async Task<ActionResult> FormatResponseAsync(
        AuthorizationRequest request,
        Endpoints.Authorization.Interfaces.AuthorizationResponse response)
    {
        switch (response)
        {
            case AccountSelectionRequired:
                return await RedirectAsync(
                    _options.Value.AccountSelectionUri.NotNull(nameof(OidcOptions.AccountSelectionUri)), response.Model);

            case ConsentRequired:
                return await RedirectAsync(
                    _options.Value.ConsentUri.NotNull(nameof(OidcOptions.ConsentUri)), response.Model);

            case InteractionRequired:
                return await RedirectAsync(
                    _options.Value.InteractionUri.NotNull(nameof(OidcOptions.InteractionUri)), response.Model);

            case LoginRequired:
                return await RedirectAsync(
                    _options.Value.LoginUri.NotNull(nameof(OidcOptions.LoginUri)), response.Model);

            case SuccessfullyAuthenticated { Model.RedirectUri: not null } success:

                var modelResponse = new AuthorizationResponse
                {
                    State = response.Model.State,
                    Scope = string.Join(' ', response.Model.Scope),

                    Code = success.Code,

                    TokenType = success.TokenType,
                    AccessToken = success.AccessToken?.EncodedJwt,

                    IdToken = success.IdToken?.EncodedJwt,

                    SessionState = success.SessionState,
                };

                var actionResult = ToActionResult(modelResponse, success.ResponseMode, response.Model.RedirectUri);

                if (_sessionManagementService.Enabled  &&
                    success.SessionId.HasValue() &&
                    response.Model.Scope.Contains(Scopes.OpenId))
                {
                    var cookie = _sessionManagementService.GetSessionCookie();

                    actionResult = actionResult.WithAppendCookie(
                        cookie.Name,
                        success.SessionId,
                        cookie.Options.ConvertOptions());
                }

                return actionResult;

            case AuthorizationError error:
                return await base.FormatResponseAsync(response.Model, error);

            default:
                throw new UnexpectedTypeException(nameof(response), response.GetType());
        }
    }

    /// <summary>
    /// Helper method to redirect the user agent to a specified URI while attaching an authorization request.
    /// </summary>
    /// <param name="uri">The base URI to redirect to.</param>
    /// <param name="request">The authorization request to attach to the URI as a query parameter.</param>
    /// <returns>A task that represents the asynchronous operation and results in a redirect action result.</returns>
    private async Task<ActionResult> RedirectAsync(Uri uri, AuthorizationRequest request)
    {
        var response = await _authorizationRequestStorage.StoreAsync(
            request,
            _options.Value.LoginSessionExpiresIn);

        if (!uri.IsAbsoluteUri)
        {
            var httpContext = _httpContextAccessor.HttpContext;

            var requestUri = new Uri(
                httpContext.NotNull(nameof(httpContext)).Request.GetDisplayUrl(),
                UriKind.Absolute);

            uri = new Uri(requestUri, uri);
        }

        return new RedirectResult(new UriBuilder(uri)
        {
            Query =
            {
                [_options.Value.RequestUriParameterName] = response.RequestUri.OriginalString,
            }
        });
    }
}
