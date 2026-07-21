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

namespace Abblix.Oidc.Client.Features.AuthorizationState;

/// <summary>
/// Registers the state consumer and the store it reads.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Adds the consumer that matches an authorization response to the login that started it.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// Registers the store as well, with the same <c>TryAdd</c> default that
    /// <c>AddAuthorizationRequests</c> uses, so consuming works whether or not the request side was
    /// added: a host that only handles the callback still resolves. Both sides naming the same default
    /// through <c>TryAdd</c> means whichever runs first sets it and the other leaves it, and a host's
    /// own store, registered before either, wins over both.
    /// </remarks>
    public static IServiceCollection AddAuthorizationStateConsumption(this IServiceCollection services)
    {
        // A soft default, so a test or a host can substitute a clock before this call.
        services.TryAddSingleton(TimeProvider.System);
        services.AddOptions<AuthorizationStateOptions>();

        // Correct for one instance only, and unbound to any user agent. A host running several replicas,
        // or one that needs the login tied to the browser that started it, replaces this - the ASP.NET
        // adapter's cookie-backed store does both. See the remarks on IAuthorizationStateStore.
        services.TryAddSingleton<IAuthorizationStateStore, InMemoryAuthorizationStateStore>();

        services.TryAddSingleton<IAuthorizationStateConsumer, AuthorizationStateConsumer>();

        return services;
    }
}
