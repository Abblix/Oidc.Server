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
