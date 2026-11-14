// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.RequestObject;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features;

/// <summary>
/// Provides extension methods to <see cref="IServiceCollection"/> for configuring request objects.
/// </summary>
public static class RequestObjectServiceCollectionExtensions
{
    /// <summary>
    /// Adds request object fetching capabilities to the dependency injection container.
    /// Registers services required for processing JWT request objects, including their validation
    /// and binding to the appropriate request properties.
    /// </summary>
    /// <param name="services">The <see cref="IServiceCollection"/> to which the user claims provider services will be
    /// added. This collection is a mechanism for adding and retrieving dependencies in .NET applications, often used
    /// to configure dependency injection in ASP.NET Core applications.</param>
    /// <returns>The updated <see cref="IServiceCollection"/> after adding the services, allowing for further
    /// modifications and additions to be chained.</returns>
    public static IServiceCollection AddRequestObject(this IServiceCollection services)
    {
        services.TryAddScoped<IRequestObjectFetcher, RequestObjectFetcher>();
        return services;
    }
}
