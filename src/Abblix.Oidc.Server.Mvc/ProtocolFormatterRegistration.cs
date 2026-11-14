// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Mvc.Formatters;
using Abblix.Oidc.Server.Mvc.Formatters.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Mvc;

/// <summary>
/// Registers the response formatters of the endpoints a client calls directly: tokens, their revocation and
/// introspection, user info, and the authorization requests sent server-to-server.
/// </summary>
internal static class ProtocolFormatterRegistration
{
	public static IServiceCollection AddOidcProtocolFormatters(this IServiceCollection services)
	{
		services.TryAddScoped<IPushedAuthorizationResponseFormatter, PushedAuthorizationResponseFormatter>();
		services.TryAddScoped<ITokenResponseFormatter, TokenResponseFormatter>();
		services.TryAddScoped<IUserInfoResponseFormatter, UserInfoResponseFormatter>();
		services.TryAddScoped<IRevocationResponseFormatter, RevocationResponseFormatter>();
		services.TryAddScoped<IIntrospectionResponseFormatter, IntrospectionResponseFormatter>();
		services.TryAddScoped<IBackChannelAuthenticationResponseFormatter, BackChannelAuthenticationResponseFormatter>();
		services.TryAddScoped<IDeviceAuthorizationResponseFormatter, DeviceAuthorizationResponseFormatter>();
		return services;
	}
}
