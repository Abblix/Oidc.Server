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

using Abblix.Oidc.Client.Features.Authorization.Context;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.Features.Authorization.Responses;

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

    /// <summary>
    /// Adds the reader that takes an authorization response apart.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// Registered on its own rather than folded into the issuer check, because the two answer different
    /// questions and a host may want its own answer to either: this one decides what the response says,
    /// that one whether the response came from the right place.
    /// </remarks>
    public static IServiceCollection AddAuthorizationResponseParsing(this IServiceCollection services)
    {
        services.TryAddSingleton<IAuthorizationResponseParser, AuthorizationResponseParser>();

        return services;
    }

    /// <summary>
    /// Adds the handler that runs an authorization response through every check in order, and the three
    /// pieces it draws on.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configure">Adjusts the RFC 9207 policies the specification leaves to the deployment.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// Composes the parser, the state consumer and the issuer validator so a host gets the whole
    /// callback-handling seam from one call, rather than three it has to remember to make in the right
    /// combination. Each part is still added through <c>TryAdd</c>, so a host that registered its own
    /// parser or store beforehand keeps it.
    /// </remarks>
    public static IServiceCollection AddAuthorizationResponseHandling(
        this IServiceCollection services,
        Action<ResponseIssuerOptions>? configure = null)
    {
        services.AddAuthorizationResponseParsing();
        services.AddResponseIssuerValidation(configure);
        services.AddAuthorizationStateConsumption();

        services.TryAddSingleton<IAuthorizationResponseHandler, AuthorizationResponseHandler>();

        return services;
    }
}
