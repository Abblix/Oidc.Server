// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.Oidc.Server.MinimalApi.Features.SessionManagement;
using Abblix.Oidc.Server.MinimalApi.Formatters;
using Abblix.Oidc.Server.MinimalApi.Formatters.Interfaces;
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
        services.TryAddScoped<IConfigurationResponseFormatter, ConfigurationResponseFormatter>();

        services.TryAddScoped<ICheckSessionResponseFormatter, CheckSessionResponseFormatter>();
        services.Decorate<ICheckSessionResponseFormatter, CheckSessionResponseCachingDecorator>();
        services.TryAddSingleton<ICheckSessionResponseCache, CheckSessionResponseCache>();

        services.TryAddScoped<IEndSessionResponseFormatter, EndSessionResponseFormatter>();
        services.Decorate<IEndSessionResponseFormatter, EndSessionResponseFormatterDecorator>();

        services.TryAddScoped<IAuthorizationResponseFormatter, AuthorizationResponseFormatter>();

        services.TryAddScoped<RegistrationClientUriBuilder>();
        services.TryAddScoped<IRegisterClientResponseFormatter, RegisterClientResponseFormatter>();
        services.TryAddScoped<IReadClientResponseFormatter, ReadClientResponseFormatter>();
        services.TryAddScoped<IUpdateClientResponseFormatter, UpdateClientResponseFormatter>();
        services.TryAddScoped<IRemoveClientResponseFormatter, RemoveClientResponseFormatter>();
        return services;
    }
}
