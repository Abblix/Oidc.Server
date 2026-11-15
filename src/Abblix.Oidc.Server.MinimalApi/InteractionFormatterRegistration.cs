// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.AspNetCore.SessionManagement;
using Abblix.Oidc.Server.AspNetCore;
using Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Abblix.Oidc.Server.AspNetCore.Formatters;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.MinimalApi;

/// <summary>
/// Registers the response formatters of discovery, of the endpoints the user's browser visits, and of client
/// management.
/// </summary>
internal static class InteractionFormatterRegistration
{
    public static IServiceCollection AddOidcInteractionFormatters(this IServiceCollection services)
    {
        services.TryAddScoped<IConfigurationResponseFormatter<IResult>, ConfigurationResponseFormatter>();

        services.TryAddScoped<ICheckSessionResponseFormatter<IResult>, CheckSessionResponseFormatter>();
        services.Decorate<ICheckSessionResponseFormatter<IResult>, CheckSessionResponseCachingDecorator>();
        services.TryAddSingleton<ICheckSessionResponseCache<IResult>, CheckSessionResponseCache<IResult>>();

        services.TryAddScoped<IEndSessionResponseFormatter<IResult>, EndSessionResponseFormatter>();
        services.Decorate<IEndSessionResponseFormatter<IResult>, EndSessionResponseFormatterDecorator>();

        services.TryAddScoped<IAuthorizationResponseFormatter<IResult>, AuthorizationResponseFormatter>();

        services.TryAddScoped<RegistrationClientUriBuilder>();
        services.TryAddScoped<IRegisterClientResponseFormatter<IResult>, RegisterClientResponseFormatter>();
        services.TryAddScoped<IReadClientResponseFormatter<IResult>, ReadClientResponseFormatter>();
        services.TryAddScoped<IUpdateClientResponseFormatter<IResult>, UpdateClientResponseFormatter>();
        services.TryAddScoped<IRemoveClientResponseFormatter<IResult>, RemoveClientResponseFormatter>();
        return services;
    }
}
