// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Server.Features.RichAuthorizationRequests;

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
    /// (RFC 9396 section 2.1). Used as the DI key; byte-exact match with the inbound entry's
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
    /// requests are rejected with <c>invalid_authorization_details</c> per RFC 9396 section 5
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
