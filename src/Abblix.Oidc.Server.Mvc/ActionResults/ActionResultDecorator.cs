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
