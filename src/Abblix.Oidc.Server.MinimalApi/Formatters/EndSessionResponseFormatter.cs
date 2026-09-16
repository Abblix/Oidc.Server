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
using Abblix.Utils;
using Microsoft.AspNetCore.Http;
using Microsoft.Net.Http.Headers;
using EndSessionRequest = Abblix.Oidc.Server.Model.EndSessionRequest;

using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;

namespace Abblix.Oidc.Server.MinimalApi.Formatters;

/// <summary>
/// Formats end-session results as <see cref="IResult"/>: a front-channel-logout HTML page (with a per-response CSP
/// nonce), a post-logout redirect, an empty 204, or the JSON OAuth error.
/// </summary>
/// <param name="frontChannelLogoutService">Builds the front-channel logout HTML response.</param>
public class EndSessionResponseFormatter(
    IFrontChannelLogoutService frontChannelLogoutService) : IEndSessionResponseFormatter
{
    /// <inheritdoc />
    public Task<IResult> FormatResponseAsync(EndSessionRequest request, Result<IEndSessionResponse, OidcError> response)
        => Task.FromResult(response.Match(
            onSuccess: FormatResponse,
            onFailure: error => Results.Json(
                new ErrorResponse(error.Error, error.ErrorDescription),
                statusCode: StatusCodes.Status400BadRequest)));

    private IResult FormatResponse(IEndSessionResponse response) => response switch
    {
        EndSessionSuccess success => FormatSuccessResponse(success),

        // The same status and error code a request lacking the answer has always been given, with the value the
        // host's page needs in order to ask for one.
        ConfirmationRequired confirmation => Results.Json(
            new ConfirmationRequiredResponse(
                ErrorCodes.ConfirmationRequired,
                "The request requires to be confirmed by user",
                confirmation.Confirmation),
            statusCode: StatusCodes.Status400BadRequest),

        _ => throw new UnexpectedTypeException(nameof(response), response.GetType()),
    };

    private IResult FormatSuccessResponse(EndSessionSuccess success)
    {
        if (success.FrontChannelLogoutRequestUris.Count > 0)
        {
            var logout = frontChannelLogoutService.GetFrontChannelLogoutResponse(
                success.PostLogoutRedirectUri,
                success.FrontChannelLogoutRequestUris);

            return Results.Content(logout.HtmlContent, MediaTypeNames.Text.Html)
                .WithHeader(HeaderNames.ContentSecurityPolicy, GetContentSecurityPolicy(logout));
        }

        if (success.PostLogoutRedirectUri != null)
            return Results.Redirect(success.PostLogoutRedirectUri.OriginalString);

        return Results.NoContent();
    }

    private static string GetContentSecurityPolicy(FrontChannelLogoutResponse response)
        => $"default-src 'none'; script-src 'nonce-{response.Nonce}'; style-src 'nonce-{response.Nonce}'; frame-src {string.Join(' ', response.FrameSources)}";
}
