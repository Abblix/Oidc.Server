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

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace Abblix.Oidc.Server.Mvc.ActionResults;

/// <summary>
/// Decorates an <see cref="ActionResult"/> by applying additional actions to the HTTP response.
/// </summary>
internal class ActionResultDecorator : ActionResult
{
    /// <summary>
    /// Initializes a new instance of the <see cref="ActionResultDecorator"/> class.
    /// </summary>
    /// <param name="innerResult">The inner <see cref="ActionResult"/> to be executed.</param>
    /// <param name="applyToResponseAction">The action to apply to the <see cref="HttpResponse"/>.</param>
    public ActionResultDecorator(
        ActionResult innerResult,
        Action<HttpResponse> applyToResponseAction)
    {
        _innerResult = innerResult;
        _applyToResponseAction = applyToResponseAction;
    }

    private readonly ActionResult _innerResult;
    private readonly Action<HttpResponse> _applyToResponseAction;

    /// <summary>
    /// Executes the result operation of the action method asynchronously.
    /// This method is called by MVC to process the result of an action method.
    /// The method applies additional actions to the response and then executes the inner result.
    /// </summary>
    /// <param name="context">The context in which the result is executed.</param>
    /// <returns>A task that represents the asynchronous execute operation.</returns>
    public override Task ExecuteResultAsync(ActionContext context)
    {
        _applyToResponseAction(context.HttpContext.Response);
        return _innerResult.ExecuteResultAsync(context);
    }

    /// <summary>
    /// Executes the result operation of the action method synchronously.
    /// This method is called by MVC to process the result of an action method.
    /// The method applies additional actions to the response and then executes the inner result.
    /// </summary>
    /// <param name="context">The context in which the result is executed.</param>
    public override void ExecuteResult(ActionContext context)
    {
        _applyToResponseAction(context.HttpContext.Response);
        _innerResult.ExecuteResult(context);
    }
}
