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


using Abblix.DependencyInjection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Registers the key ring.
/// </summary>
public static class KeyRingServiceCollectionExtensions
{
    /// <summary>
    /// Registers a key ring that mints its own keys, seals each to the custodian's key-encryption key, shares
    /// them through the registered <see cref="IKeyRingStore"/>, and rotates them on the policy's schedule.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="policy">What to mint, how often, and which key-encryption key seals it.</param>
    /// <returns>A builder for the call that supplies the store.</returns>
    /// <remarks>
    /// This registers the ring and nothing else. What the ring's keys are then USED for is the caller's
    /// concern: an OpenID Provider publishes them at its JWKS endpoint, a client protects stored sessions with
    /// them. Neither of those belongs here, which is why this lives beside the key material rather than beside
    /// either consumer.
    /// </remarks>
    public static IMintedKeysBuilder AddKeyRing(this IServiceCollection services, MintedKeys policy)
    {
        services.TryAddSingleton<KeyEnvelope>();

        // CreateService, unlike the plain registrations around it, because the policy is a per-call value the
        // container knows nothing about: everything else the ring needs is resolved normally.
        services.TryAddSingleton<IKeyRing>(
            serviceProvider => serviceProvider.CreateService<KeyRing>(Dependency.Override(policy)));

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, KeyRingRefreshService>());

        return new MintedKeysBuilder(services);
    }
}
