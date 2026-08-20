// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Validation;
using Abblix.Oidc.Server.Mvc.ActionResults;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Renders a failed model-validation pass as the OAuth <c>invalid_request</c> error instead of the
/// <c>[ApiController]</c> default <see cref="Microsoft.AspNetCore.Mvc.ValidationProblemDetails"/> 400, so the
/// rejection joins the JSON error envelope every other rejection on these endpoints uses. Applied to this
/// library's own OIDC controllers, which confines the OAuth shape to them and leaves a host's own controllers
/// on their default validation response.
/// </summary>
/// <remarks>
/// Implemented as a controller attribute rather than a globally registered filter so it is pure controller
/// metadata: it mutates no global option (notably not
/// <c>ApiBehaviorOptions.InvalidModelStateResponseFactory</c>), so a host cannot clobber it by reconfiguring
/// its own MVC pipeline and the OIDC endpoints cannot affect the host's. It is ordered just before the
/// framework's <c>ModelStateInvalidFilter</c> (Order -2000) and short-circuits with the OAuth result, so the
/// automatic ProblemDetails response is never produced here.
/// </remarks>
[AttributeUsage(AttributeTargets.Class, Inherited = true)]
internal sealed class ReturnsOidcInvalidRequestAttribute : Attribute, IActionFilter, IOrderedFilter
{
	// The framework's ModelStateInvalidFilter (the [ApiController] auto-400) runs at Order -2000; one step
	// earlier lets this filter emit the OAuth error before that automatic ProblemDetails is set.
	private const int OrderBeforeApiControllerValidation = -2001;

	/// <inheritdoc />
	public int Order => OrderBeforeApiControllerValidation;

	/// <inheritdoc />
	public void OnActionExecuting(ActionExecutingContext context)
	{
		if (context.ModelState.IsValid)
			return;

		var messages =
			from entry in context.ModelState
			from error in entry.Value.Errors
			select error.ErrorMessage;

		context.Result = ErrorFactory.InvalidRequest(messages).Format(StatusCodes.Status400BadRequest);
	}

	/// <inheritdoc />
	public void OnActionExecuted(ActionExecutedContext context)
	{
	}
}
