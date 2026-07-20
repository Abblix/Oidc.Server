// Abblix OIDC Client Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.Features.AuthorizationResponses;

/// <summary>
/// Registers the authorization-response checks.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the RFC 9207 issuer check that decides whether a response came from the expected provider.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">Adjusts the two policies the specification leaves to the deployment.</param>
    /// <returns>The same collection, so calls chain.</returns>
    public static IServiceCollection AddResponseIssuerValidation(
        this IServiceCollection services,
        Action<ResponseIssuerOptions>? configure = null)
    {
        // Unconditionally, not only when there is something to configure: without it IOptions<T> has no
        // registration at all and the validator cannot be constructed, so a host that accepted every
        // default would be the one host unable to resolve the service.
        services.AddOptions<ResponseIssuerOptions>();

        if (configure is not null)
            services.Configure(configure);

        services.TryAddSingleton<IResponseIssuerValidator, ResponseIssuerValidator>();

        return services;
    }
}
