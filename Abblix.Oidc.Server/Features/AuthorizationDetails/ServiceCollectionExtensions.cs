// Abblix OIDC Server Library
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

namespace Abblix.Oidc.Server.Features.AuthorizationDetails;

/// <summary>
/// Service-collection extensions for the RFC 9396 Rich Authorization Requests feature.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers a per-type validator for RFC 9396 authorization_details entries whose
    /// <c>type</c> value matches <paramref name="type"/>. The composite
    /// <see cref="IAuthorizationDetailsPolicy"/> dispatches each entry in the
    /// authorization_details array to the implementation keyed by the entry's <c>type</c>.
    /// </summary>
    /// <typeparam name="TValidator">The per-type validator implementation.</typeparam>
    /// <param name="services">The service collection to register the validator in.</param>
    /// <param name="type">The authorization-detail <c>type</c> value the validator handles
    /// (RFC 9396 §2.1). Used as the DI key; byte-exact match with the inbound entry's
    /// <c>type</c> member.</param>
    /// <returns>The service collection for method chaining.</returns>
    /// <remarks>
    /// A single keyed registration via
    /// <see cref="ServiceCollectionDescriptorExtensions.TryAddKeyedSingleton{TService, TImplementation}(IServiceCollection, object)"/>
    /// serves both O(1) request-time dispatch
    /// (<c>GetKeyedService&lt;IAuthorizationDetailValidator&gt;(type)</c>) and discovery
    /// enumeration in slice #132 via
    /// <c>GetKeyedServices&lt;IAuthorizationDetailValidator&gt;(KeyedService.AnyKey)</c>
    /// (.NET 8+). No <c>TryAddEnumerable</c> parallel slot.
    /// </remarks>
    public static IServiceCollection AddAuthorizationDetailValidator<TValidator>(
        this IServiceCollection services,
        string type)
        where TValidator : class, IAuthorizationDetailValidator
    {
        services.TryAddKeyedSingleton<IAuthorizationDetailValidator, TValidator>(type);
        return services;
    }

    /// <summary>
    /// Registers the OAuth 2.0 Rich Authorization Requests (RFC 9396) infrastructure: the
    /// composite <see cref="IAuthorizationDetailsPolicy"/> and the
    /// <see cref="IAuthorizationDetailsMetadataProvider"/> discovery contributor. Called
    /// unconditionally from <c>AddFeatures</c> so the server boots cleanly with zero
    /// <see cref="IAuthorizationDetailValidator"/> implementations registered; RAR-bearing
    /// requests are rejected with <c>invalid_authorization_details</c> per RFC 9396 §5
    /// until at least one validator is registered via
    /// <see cref="AddAuthorizationDetailValidator{TValidator}"/>.
    /// </summary>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The service collection for method chaining.</returns>
    public static IServiceCollection AddRichAuthorizationRequests(this IServiceCollection services)
    {
        services.TryAddSingleton<IAuthorizationDetailsPolicy, AuthorizationDetailsPolicy>();
        services.TryAddSingleton<IAuthorizationDetailsMetadataProvider, AuthorizationDetailsMetadataProvider>();
        return services;
    }
}
