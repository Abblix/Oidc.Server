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

using System.Net.Mime;
using Abblix.Oidc.Server.Common;
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
    public Task<IResult> FormatResponseAsync(EndSessionRequest request, Result<EndSessionSuccess, OidcError> response)
        => Task.FromResult(response.Match(
            onSuccess: FormatSuccessResponse,
            onFailure: error => Results.Json(
                new ErrorResponse(error.Error, error.ErrorDescription),
                statusCode: StatusCodes.Status400BadRequest)));

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
