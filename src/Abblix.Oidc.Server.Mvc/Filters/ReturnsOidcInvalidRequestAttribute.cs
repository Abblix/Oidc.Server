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
/// Answers a failed model-binding or validation pass with the OAuth <c>invalid_request</c> error before the action
/// runs, so the rejection joins the JSON error envelope every other rejection on these endpoints uses. Applied to
/// this library's own OIDC controllers, which confines the OAuth shape to them and leaves a host's own controllers
/// on their own validation response.
/// </summary>
/// <remarks>
/// Implemented as a controller attribute rather than a globally registered filter so it is pure controller
/// metadata: it mutates no global option (notably not
/// <c>ApiBehaviorOptions.InvalidModelStateResponseFactory</c>), so a host cannot clobber it by reconfiguring
/// its own MVC pipeline and the OIDC endpoints cannot affect the host's.
/// </remarks>
[AttributeUsage(AttributeTargets.Class, Inherited = true)]
internal sealed class ReturnsOidcInvalidRequestAttribute : Attribute, IActionFilter, IOrderedFilter
{
	// One step ahead of the framework's ModelStateInvalidFilter (Order -2000), so the OAuth error stays first on any
	// action that filter reaches.
	private const int OrderBeforeApiControllerValidation = -2001;

	/// <inheritdoc />
	public int Order => OrderBeforeApiControllerValidation;

	/// <inheritdoc />
	public void OnActionExecuting(ActionExecutingContext context)
	{
		if (context.ModelState.IsValid)
			return;

		// The first failure on a parameter is its cause: a refused repetition leaves the parameter unbound, and a
		// required one then also reports its value missing, which says nothing the first message did not
		var messages =
			from entry in context.ModelState
			where entry.Value.Errors.Count > 0
			select entry.Value.Errors[0].ErrorMessage;

		context.Result = ErrorFactory.InvalidRequest(messages).Format(StatusCodes.Status400BadRequest);
	}

	/// <inheritdoc />
	public void OnActionExecuted(ActionExecutedContext context)
	{
	}
}
