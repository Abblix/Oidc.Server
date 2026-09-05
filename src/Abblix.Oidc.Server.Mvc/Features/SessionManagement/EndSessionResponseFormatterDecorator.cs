// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore;
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
/// <param name="inner">The inner End Session response formatter.</param>
/// <param name="sessionManagementService">The service responsible for session management.</param>
public class EndSessionResponseFormatterDecorator(
    IEndSessionResponseFormatter inner,
    ISessionManagementService sessionManagementService): IEndSessionResponseFormatter
{
    /// <summary>
    /// Formats an End Session response and performs session management operations if enabled.
    /// </summary>
    /// <param name="request">The End Session request.</param>
    /// <param name="response">The End Session response to be formatted.</param>
    /// <returns>
    /// A <see cref="Task{TResult}"/> representing the asynchronous operation. The task result contains
    /// the formatted ActionResult, with additional session management actions if enabled.
    /// </returns>
    public async Task<ActionResult> FormatResponseAsync(EndSessionRequest request, Result<EndSessionSuccess, OidcError> response)
    {
        var result = await inner.FormatResponseAsync(request, response);

        if (sessionManagementService.Enabled)
        {
            var cookie = sessionManagementService.GetSessionCookie();
            result = result.WithDeleteCookie(cookie.Name, cookie.Options.ConvertOptions());
        }

        return result;
    }
}
