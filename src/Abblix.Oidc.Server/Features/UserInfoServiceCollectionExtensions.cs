// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.PairwiseIdentifiers;
using Abblix.Oidc.Server.Features.ResourceIndicators;
using Abblix.Oidc.Server.Features.ScopeManagement;
using Abblix.Oidc.Server.Features.UserInfo;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring user claims and subject identifiers.
/// </summary>
public static class UserInfoServiceCollectionExtensions
{
    /// <summary>
    /// Registers services related to user claims management into the provided <see cref="IServiceCollection"/>.
    /// This method sets up essential services required for processing and handling user claims based on authentication
    /// sessions and authorization requests, facilitating the integration of user-specific data into tokens or responses.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to which the user claims provider services will be
    /// added. This collection is a mechanism for adding and retrieving dependencies in .NET applications, often used
    /// to configure dependency injection in ASP.NET Core applications.</param>
    /// <returns>The updated <see cref="IServiceCollection"/> after adding the services, allowing for further
    /// modifications and additions to be chained.</returns>
    public static IServiceCollection AddUserInfo(this IServiceCollection services)
    {
        services.TryAddScoped<IUserClaimsProvider, UserClaimsProvider>();

        // A host keeping no users, as one serving client credentials alone, registers no provider of user
        // information, and the services issuing tokens still have to be built; a host's own replaces this one
        services.TryAddSingleton<IUserInfoProvider, NoUserInfoProvider>();
        services.TryAddSingleton<ISubjectTypeConverter, IssuerSubjectTypeConverter>();
        services.TryAddSingleton<IScopeClaimsProvider, ScopeClaimsProvider>();
        services.TryAddSingleton<IScopeManager, ScopeManager>();
        services.TryAddSingleton<IResourceManager, ResourceManager>();
        services.TryAddSingleton<ResourceInference>();
        services.TryAddSingleton<IResourceKeysProvider, ResourceKeysProvider>();
        services.TryAddSingleton<IAudienceKeyResolver, AudienceKeyResolver>();
        return services;
    }
}
