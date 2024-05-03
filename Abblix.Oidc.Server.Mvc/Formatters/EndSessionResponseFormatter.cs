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

using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Formatters;

/// <summary>
/// Provides a response formatter for end-session requests, which is part of the OpenID Connect protocol.
/// </summary>
public class EndSessionResponseFormatter : IEndSessionResponseFormatter
{
    /// <summary>
    /// Formats an end-session response asynchronously based on the provided response model.
    /// </summary>
    /// <param name="request">The end-session request.</param>
    /// <param name="response">The end-session response model.</param>
    /// <returns>
    /// A <see cref="Task"/> representing the asynchronous operation, with the formatted response as an <see cref="ActionResult"/>.
    /// </returns>
    public Task<ActionResult> FormatResponseAsync(EndSessionRequest request, EndSessionResponse response)
        => Task.FromResult(FormatResponse(response));

    private static ActionResult FormatResponse(EndSessionResponse response)
    {
        switch (response)
        {
            case EndSessionSuccessfulResponse success:

                ActionResult result;
                if (success.FrontChannelLogoutRequestUris.Count > 0)
                {
                    result = new FrontChannelLogoutResult(
                        success.PostLogoutRedirectUri,
                        success.FrontChannelLogoutRequestUris);
                }
                else if (success.PostLogoutRedirectUri != null)
                {
                    result = new RedirectResult(success.PostLogoutRedirectUri.OriginalString);
                }
                else
                {
                    result = new NoContentResult();
                }

                return result;

            case EndSessionErrorResponse { Error: var error, ErrorDescription: var description }:
                return new BadRequestObjectResult(new ErrorResponse(error, description));

            default:
                throw new ArgumentOutOfRangeException(nameof(response));
        }
    }
}
