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


using Abblix.Oidc.Client.Features.AuthorizationState;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.Oidc.Client.Features.AuthorizationRequests;

/// <summary>
/// Registers the building of authorization requests.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the builder of authorization requests, together with the PKCE values and the request state it
    /// depends on.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="configureOptions">A delegate that configures <see cref="AuthorizationRequestOptions"/>.</param>
    /// <returns>The same collection, so calls chain.</returns>
    public static IServiceCollection AddAuthorizationRequests(
        this IServiceCollection services, Action<AuthorizationRequestOptions> configureOptions)
    {
        services.Configure(configureOptions);

        // A soft default, so a test or a host can substitute a clock before this call.
        services.TryAddSingleton(TimeProvider.System);

        services.TryAddSingleton<Pkce.IPkceProvider, Pkce.PkceProvider>();
        services.TryAddSingleton<IAuthorizationRequestBuilder, AuthorizationRequestBuilder>();

        // Correct for one instance only. A host running several replicas replaces this with a store the
        // callback can reach whichever replica it lands on - the ASP.NET adapter's cookie-backed one.
        services.TryAddSingleton<
            IAuthorizationStateStore,
            InMemoryAuthorizationStateStore>();

        return services;
    }
}
