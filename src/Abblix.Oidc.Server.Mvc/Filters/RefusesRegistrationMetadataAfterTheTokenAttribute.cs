// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.AspNetCore.Formatters;
using Abblix.Oidc.Server.Endpoints.DynamicClientManagement.Interfaces;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.Oidc.Server.Mvc.Binders;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Refuses a registration whose body cannot be read by its initial access token first, where the server requires one.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
internal sealed class RefusesRegistrationMetadataAfterTheTokenAttribute : RefusesClientMetadataAfterTheTokenAttribute
{
	/// <inheritdoc />
	protected override async Task<ActionResult?> RefuseByTheTokenAsync(ActionExecutingContext context)
	{
		// The lines as the action reads them, through the binder of its Authorization parameter
		var lines = context.ActionDescriptor.Parameters
			.Where(parameter => parameter.BindingInfo?.BinderType == typeof(AuthenticationHeaderBinder))
			.Select(parameter => context.ActionArguments.TryGetValue(parameter.Name, out var value) ? value : null)
			.Cast<IReadOnlyList<string>?>()
			.Single();

		var services = context.HttpContext.RequestServices;
		var tokenError = await services.GetRequiredService<IInitialAccessTokenValidator>()
			.ValidateAsync(services.GetRequiredService<ITenantAccessor>().CurrentTenant(), lines);

		if (tokenError is null)
			return null;

		// The refused body holds no metadata, and a failure is formatted from the error alone
		return await services.GetRequiredService<IRegisterClientResponseFormatter<ActionResult>>().FormatResponseAsync(
			new Core.ClientRegistrationRequest { AuthorizationHeaderLines = lines }, tokenError);
	}
}
