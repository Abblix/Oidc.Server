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
using Abblix.Oidc.Server.Features.SessionManagement;
using Abblix.Oidc.Server.Model;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
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
    public async Task<ActionResult> FormatResponseAsync(EndSessionRequest request, EndSessionResponse response)
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
