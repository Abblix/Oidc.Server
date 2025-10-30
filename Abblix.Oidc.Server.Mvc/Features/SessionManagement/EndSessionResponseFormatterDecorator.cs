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

using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Endpoints.EndSession.Interfaces;
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.Features.SessionManagement;

/// <summary>
/// A decorator class that adds session management functionality to the End Session response formatting process.
/// </summary>
public class EndSessionResponseFormatterDecorator: IEndSessionResponseFormatter
{
    /// <summary>
    /// Initializes a new instance of the <see cref="EndSessionResponseFormatterDecorator"/> class.
    /// </summary>
    /// <param name="inner">The inner End Session response formatter.</param>
    /// <param name="sessionManagementService">The service responsible for session management.</param>
    public EndSessionResponseFormatterDecorator(
        IEndSessionResponseFormatter inner,
        ISessionManagementService sessionManagementService)
    {
        _inner = inner;
        _sessionManagementService = sessionManagementService;
    }

    private readonly IEndSessionResponseFormatter _inner;
    private readonly ISessionManagementService _sessionManagementService;

    /// <summary>
    /// Formats an End Session response and performs session management operations if enabled.
    /// </summary>
    /// <param name="request">The End Session request.</param>
    /// <param name="response">The End Session response to be formatted.</param>
    /// <returns>
    /// A <see cref="Task{TResult}"/> representing the asynchronous operation. The task result contains
    /// the formatted ActionResult, with additional session management actions if enabled.
    /// </returns>
    public async Task<ActionResult> FormatResponseAsync(EndSessionRequest request, Result<EndSessionSuccess, AuthError> response)
    {
        var result = await _inner.FormatResponseAsync(request, response);

        if (_sessionManagementService.Enabled)
        {
            var cookie = _sessionManagementService.GetSessionCookie();
            result = result.WithDeleteCookie(cookie.Name, cookie.Options.ConvertOptions());
        }

        return result;
    }
}
