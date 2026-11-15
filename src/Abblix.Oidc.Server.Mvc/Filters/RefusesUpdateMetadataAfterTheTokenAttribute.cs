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
using Abblix.Oidc.Server.Mvc.Model;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.Extensions.DependencyInjection;
using Core = Abblix.Oidc.Server.Model;

namespace Abblix.Oidc.Server.Mvc.Filters;

/// <summary>
/// Refuses an update whose body cannot be read by its registration access token first.
/// </summary>
[AttributeUsage(AttributeTargets.Method)]
internal sealed class RefusesUpdateMetadataAfterTheTokenAttribute : RefusesClientMetadataAfterTheTokenAttribute
{
	/// <inheritdoc />
	protected override async Task<ActionResult?> RefuseByTheTokenAsync(ActionExecutingContext context)
	{
		Core.ClientRequest clientRequest = context.ActionArguments.Values.OfType<ClientAuthorizationRequest>().Single();

		var services = context.HttpContext.RequestServices;
		var validation = await services.GetRequiredService<IClientRequestValidator>()
			.ValidateAsync(services.GetRequiredService<ITenantAccessor>().CurrentTenant(), clientRequest);

		if (!validation.TryGetFailure(out var error))
			return null;

		// The refused body holds no metadata, and a failure is formatted from the error alone
		return await services.GetRequiredService<IUpdateClientResponseFormatter<ActionResult>>().FormatResponseAsync(
			new UpdateClientRequest(clientRequest, new Core.ClientRegistrationRequest()), error);
	}
}
