// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Net.Mime;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Common.Exceptions;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for end-session requests, which is part of the OpenID Connect protocol.
/// </summary>
/// <param name="frontChannelLogoutService">Service for generating front-channel logout HTML responses.</param>
public class EndSessionResponseFormatter(
    IFrontChannelLogoutService frontChannelLogoutService) : IEndSessionResponseFormatter
{
    /// <summary>
    /// Formats an end-session response asynchronously based on the provided response model.
    /// </summary>
    /// <param name="request">The end-session request.</param>
    /// <param name="response">The end-session response model.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult"/>.
    /// </returns>
    public Task<ActionResult> FormatResponseAsync(EndSessionRequest request, Result<IEndSessionResponse, OidcError> response)
        => Task.FromResult(response.Match(
            onSuccess: FormatResponse,
            onFailure: error => new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))));

    private ActionResult FormatResponse(IEndSessionResponse response) => response switch
    {
        EndSessionSuccess success => FormatSuccessResponse(success),

        // The same status and error code a request lacking the answer has always been given, with the value the
        // host's page needs in order to ask for one.
        ConfirmationRequired confirmation => new BadRequestObjectResult(
            new ConfirmationRequiredResponse(
                ErrorCodes.ConfirmationRequired,
                "The request requires to be confirmed by user",
                confirmation.Confirmation)),

        _ => throw new UnexpectedTypeException(nameof(response), response.GetType()),
    };

    private ActionResult FormatSuccessResponse(EndSessionSuccess success)
    {
        if (success.FrontChannelLogoutRequestUris.Count > 0)
        {
            var response = frontChannelLogoutService.GetFrontChannelLogoutResponse(
                success.PostLogoutRedirectUri,
                success.FrontChannelLogoutRequestUris);

            return new ContentResult { Content = response.HtmlContent, ContentType = MediaTypeNames.Text.Html }
                .WithHeader(HeaderNames.ContentSecurityPolicy, GetContentSecurityPolicy(response));
        }

        if (success.PostLogoutRedirectUri != null)
        {
            return new RedirectResult(success.PostLogoutRedirectUri.OriginalString);
        }

        return new NoContentResult();
    }

    /// <summary>
    /// Gets the Content-Security-Policy header value for this logout page.
    /// </summary>
    /// <param name="response"></param>
    internal static string GetContentSecurityPolicy(FrontChannelLogoutResponse response)
        => $"default-src 'none'; script-src 'nonce-{response.Nonce}'; style-src 'nonce-{response.Nonce}'; frame-src {string.Join(' ', response.FrameSources)}";
}
