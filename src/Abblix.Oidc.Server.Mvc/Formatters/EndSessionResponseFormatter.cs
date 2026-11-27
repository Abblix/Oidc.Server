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
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.AspNetCore.Formatters;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Net.Http.Headers;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for end-session requests, which is part of the OpenID Connect protocol.
/// </summary>
/// <param name="frontChannelLogoutService">Service for generating front-channel logout HTML responses.</param>
/// <param name="tenantAccessor">Supplies the tenant whose confirmation page asks the end user.</param>
/// <param name="uriResolver">Resolves a relative confirmation page to an absolute address.</param>
public class EndSessionResponseFormatter(
    IFrontChannelLogoutService frontChannelLogoutService,
    ITenantAccessor tenantAccessor,
    IUriResolver uriResolver) : IEndSessionResponseFormatter<ActionResult>
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
            onSuccess: success => FormatResponse(request, success),
            onFailure: error => new BadRequestObjectResult(new ErrorResponse(error.Error, error.ErrorDescription))));

    private ActionResult FormatResponse(EndSessionRequest request, IEndSessionResponse response) => response switch
    {
        EndSessionSuccess success => FormatSuccessResponse(success),
        ConfirmationRequired confirmation => AskTheEndUser(request, confirmation),
        _ => throw new UnexpectedTypeException(nameof(response), response.GetType()),
    };

    /// <summary>
    /// Sends the user agent to the tenant's confirmation page, the way the authorization endpoint sends it to the
    /// login page.
    /// </summary>
    /// <remarks>
    /// A tenant with no such page gets the status and error code a request lacking the answer has always been given,
    /// with the value a page of the host's own needs in order to ask for one.
    /// </remarks>
    private ActionResult AskTheEndUser(EndSessionRequest request, ConfirmationRequired confirmation)
    {
        if (tenantAccessor.CurrentTenant().LogoutConfirmationUri is not { } page)
        {
            return new BadRequestObjectResult(
                new ConfirmationRequiredResponse(
                    ErrorCodes.ConfirmationRequired,
                    "The request requires to be confirmed by user",
                    confirmation.Confirmation));
        }

        if (!page.IsAbsoluteUri)
            page = uriResolver.Content(page.OriginalString);

        return new SeeOtherResult(LogoutConfirmationPage.Address(page, request, confirmation.Confirmation))
            .WithHeader(ReferrerPolicy.HeaderName, ReferrerPolicy.NoReferrer);
    }

    private ActionResult FormatSuccessResponse(EndSessionSuccess success)
    {
        if (success.FrontChannelLogoutRequestUris.Count > 0)
        {
            var response = frontChannelLogoutService.GetFrontChannelLogoutResponse(
                success.PostLogoutRedirectUri,
                success.FrontChannelLogoutRequestUris);

            return new ContentResult { Content = response.HtmlContent, ContentType = MediaTypeNames.Text.Html }
                .WithHeader(HeaderNames.ContentSecurityPolicy, FrontChannelLogoutPage.ContentSecurityPolicy(response))
                .WithHeader(HeaderNames.XFrameOptions, AntiFramingHeaders.XFrameOptions);
        }

        if (success.PostLogoutRedirectUri != null)
        {
            return new RedirectResult(success.PostLogoutRedirectUri.OriginalString);
        }

        return new NoContentResult();
    }
}
