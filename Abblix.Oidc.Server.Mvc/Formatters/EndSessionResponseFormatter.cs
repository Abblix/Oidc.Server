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
    public Task<ActionResult> FormatResponseAsync(EndSessionRequest request, Result<EndSessionSuccess, OidcError> response)
        => Task.FromResult(response.Match(
            onSuccess: FormatSuccessResponse,
            onFailure: error => new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))));

    private ActionResult FormatSuccessResponse(EndSessionSuccess success)
    {
        if (success.FrontChannelLogoutRequestUris.Count > 0)
        {
            var response = frontChannelLogoutService.GetFrontChannelLogoutResponse(
                success.PostLogoutRedirectUri,
                success.FrontChannelLogoutRequestUris);

            return new ContentResult { Content = response.HtmlContent, ContentType = MediaTypeNames.Text.Html }
                .WithNoCacheHeaders()
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
