// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.AspNetCore.SessionManagement;
using Abblix.Oidc.Server.Mvc.Features.SessionManagement;
using Abblix.Oidc.Server.Mvc.Formatters;
using Abblix.Oidc.Server.AspNetCore.Formatters;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Registers the response formatters of discovery, of the endpoints the user's browser visits, and of client
/// management.
/// </summary>
internal static class InteractionFormatterRegistration
{
	public static IServiceCollection AddOidcInteractionFormatters(this IServiceCollection services)
	{
		services.TryAddScoped<IConfigurationResponseFormatter<ActionResult>, ConfigurationResponseFormatter>();
		services.TryAddScoped<IAuthorizationResponseFormatter<ActionResult>, AuthorizationResponseFormatter>();

		services.TryAddScoped<IEndSessionResponseFormatter<ActionResult>, EndSessionResponseFormatter>();
		services.Decorate<IEndSessionResponseFormatter<ActionResult>, EndSessionResponseFormatterDecorator>();

		services.TryAddScoped<ICheckSessionResponseFormatter<ActionResult>, CheckSessionResponseFormatter>();
		services.Decorate<ICheckSessionResponseFormatter<ActionResult>, CheckSessionResponseCachingDecorator>();
		services.TryAddSingleton<ICheckSessionResponseCache<ActionResult>, CheckSessionResponseCache<ActionResult>>();

		services.TryAddScoped<IRegisterClientResponseFormatter<ActionResult>, RegisterClientResponseFormatter>();
		services.TryAddScoped<IReadClientResponseFormatter<ActionResult>, ReadClientResponseFormatter>();
		services.TryAddScoped<IUpdateClientResponseFormatter<ActionResult>, UpdateClientResponseFormatter>();
		services.TryAddScoped<IRemoveClientResponseFormatter<ActionResult>, RemoveClientResponseFormatter>();
		return services;
	}
}
