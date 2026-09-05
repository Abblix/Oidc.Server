// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.ActionResults;

/// <summary>
/// Decorates an <see cref="ActionResult"/> by applying additional actions to the HTTP response.
/// </summary>
/// <param name="innerResult">The inner <see cref="ActionResult"/> to be executed.</param>
/// <param name="applyToResponseAction">The action to apply to the <see cref="HttpResponse"/>.</param>
internal class ActionResultDecorator(
    ActionResult innerResult,
    Action<HttpResponse> applyToResponseAction) : ActionResult
{
    /// <summary>
    /// Executes the result operation of the action method asynchronously.
    /// This method is called by MVC to process the result of an action method.
    /// The method applies additional actions to the response and then executes the inner result.
    /// </summary>
    /// <param name="context">The context in which the result is executed.</param>
    /// <returns>A task that represents the asynchronous execute operation.</returns>
    public override Task ExecuteResultAsync(ActionContext context)
    {
        applyToResponseAction(context.HttpContext.Response);
        return innerResult.ExecuteResultAsync(context);
    }

    /// <summary>
    /// Executes the result operation of the action method synchronously.
    /// This method is called by MVC to process the result of an action method.
    /// The method applies additional actions to the response and then executes the inner result.
    /// </summary>
    /// <param name="context">The context in which the result is executed.</param>
    public override void ExecuteResult(ActionContext context)
    {
        applyToResponseAction(context.HttpContext.Response);
        innerResult.ExecuteResult(context);
    }
}
