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
using Microsoft.AspNetCore.Mvc.ModelBinding;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Refuses a client metadata body that could not be read as <see cref="ErrorFactory.UnreadableClientMetadata"/>,
/// the answer the Minimal API host gives, instead of the <c>invalid_request</c> built from the JSON parser's messages,
/// which quote the body and name the server's types.
/// </summary>
/// <remarks>
/// A body that could not be read leaves its parameter unbound, so the arguments of the action, not the wording of
/// the model state, tell that it failed. Applied to the registration and update actions only, it runs just before
/// <see cref="ReturnsOidcInvalidRequestAttribute"/>, which answers every other parameter that failed.
/// </remarks>
[AttributeUsage(AttributeTargets.Method)]
internal sealed class RefusesUnreadableClientMetadataAttribute : Attribute, IActionFilter, IOrderedFilter
{
	// One step ahead of ReturnsOidcInvalidRequestAttribute, which runs at -2001
	private const int OrderBeforeInvalidRequest = -2002;

	/// <inheritdoc />
	public int Order => OrderBeforeInvalidRequest;

	/// <inheritdoc />
	public void OnActionExecuting(ActionExecutingContext context)
	{
		var bodyUnbound = context.ActionDescriptor.Parameters
			.Where(parameter => parameter.BindingInfo?.BindingSource == BindingSource.Body)
			.Any(parameter => !context.ActionArguments.TryGetValue(parameter.Name, out var value) || value is null);

		if (bodyUnbound)
			context.Result = ErrorFactory.UnreadableClientMetadata.Format(StatusCodes.Status400BadRequest);
	}

	/// <inheritdoc />
	public void OnActionExecuted(ActionExecutedContext context)
	{
	}
}
