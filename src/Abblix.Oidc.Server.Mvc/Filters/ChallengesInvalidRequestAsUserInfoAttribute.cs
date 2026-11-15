// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.Formatters;
using Abblix.Oidc.Server.Common;
using Abblix.Utils;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Answers a failed model-binding or validation pass at the UserInfo Endpoint through the endpoint's own formatter,
/// which carries the WWW-Authenticate challenges. The endpoint is a protected resource (OpenID Connect Core 1.0
/// section 1.2), and RFC 6750 section 3 has a request that "does not contain an access token that enables access to
/// the protected resource" answered with that field, a request the binder refused included.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
internal sealed class ChallengesInvalidRequestAsUserInfoAttribute : Attribute, IAsyncActionFilter, IOrderedFilter
{
	// One step ahead of ReturnsOidcInvalidRequestAttribute, which runs at -2001 and would answer without the challenges
	private const int OrderBeforeInvalidRequest = -2002;

	/// <inheritdoc />
	public int Order => OrderBeforeInvalidRequest;

	/// <inheritdoc />
	public async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
	{
		if (context.ModelState.IsValid)
		{
			await next();
			return;
		}

		// The refused request has no token the formatter could read, and a failure is formatted from the error alone
		var formatter = context.HttpContext.RequestServices.GetRequiredService<IUserInfoResponseFormatter<ActionResult>>();
		context.Result = await formatter.FormatResponseAsync(
			new Core.UserInfoRequest(),
			ReturnsOidcInvalidRequestAttribute.InvalidRequestOf(context.ModelState));
	}
}
