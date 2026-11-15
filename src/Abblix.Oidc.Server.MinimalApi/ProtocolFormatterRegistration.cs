// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Abblix.Oidc.Server.AspNetCore.Formatters;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Registers the response formatters of the endpoints a client calls directly: tokens, their revocation and
/// introspection, user info, and the authorization requests sent server-to-server.
/// </summary>
internal static class ProtocolFormatterRegistration
{
    public static IServiceCollection AddOidcProtocolFormatters(this IServiceCollection services)
    {
        services.TryAddScoped<ITokenResponseFormatter<IResult>, TokenResponseFormatter>();
        services.TryAddScoped<IRevocationResponseFormatter<IResult>, RevocationResponseFormatter>();
        services.TryAddScoped<IIntrospectionResponseFormatter<IResult>, IntrospectionResponseFormatter>();
        services.TryAddScoped<IPushedAuthorizationResponseFormatter<IResult>, PushedAuthorizationResponseFormatter>();
        services.TryAddScoped<IBackChannelAuthenticationResponseFormatter<IResult>, BackChannelAuthenticationResponseFormatter>();
        services.TryAddScoped<IDeviceAuthorizationResponseFormatter<IResult>, DeviceAuthorizationResponseFormatter>();
        services.TryAddScoped<IUserInfoResponseFormatter<IResult>, UserInfoResponseFormatter>();
        return services;
    }
}
