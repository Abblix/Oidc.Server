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
using Microsoft.Extensions.Options;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Registers the pieces of external key custody: the custodian placement choice and the key ring.
/// </summary>
public static class ExternalKeysServiceCollectionExtensions
{
    /// <summary>
    /// Requires the host to say where the private half of its keys lives, and hands it the builder to say it with.
    /// </summary>
    /// <param name="services">The service collection holding the custodian registration.</param>
    /// <returns>The builder whose placement call completes the wiring.</returns>
    /// <remarks>
    /// Which custodian holds the keys and how the library uses it are two independent choices, so they are two
    /// calls: this one opens the second. Nothing is decided here, and that is the point - a custodian with no
    /// placement chosen is a half-wired host, and it fails at startup rather than picking a posture on the host's
    /// behalf.
    ///
    /// Registered by the backend packages, which know their custodian and nothing about what it will be used
    /// for. What the placement calls then do with it belongs to whoever consumes the keys.
    /// </remarks>
    public static IKeyCustodianBuilder RequireKeyPlacement(this IServiceCollection services)
    {
        // Turns a missing placement call into a startup failure rather than a first-use one: the host runs its
        // startup validators before it starts the hosted service that opens the port, so the process never
        // serves a request in this state.
        services.AddOptions<KeyPlacementChoice>()
            .Validate(choice => choice.ChosenPlacement is not null, KeyPlacementChoice.PlacementNotChosenMessage)
            .ValidateOnStart();

        return new KeyCustodianBuilder(services);
    }

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

    /// <summary>
    /// Registers a key ring that mints its keys in this process and keeps them there: no custodian, no shared
    /// store, nothing to provision.
    /// </summary>
    /// <param name="services">The service collection to add to.</param>
    /// <param name="policy">What to mint, how often, and how long to keep a retired key.</param>
    /// <returns>The same collection, so calls chain.</returns>
    /// <remarks>
    /// The answer for a host with no HSM or KMS, which is most of them. It rotates, and it keeps retired keys
    /// long enough that what they produced stays readable - the two things a ring is for.
    ///
    /// What it does NOT do is share those keys with another process. Every replica mints its own, so anything
    /// one replica produced is unreadable by the others, and everything is gone when the process restarts.
    /// For a single instance that is exactly right and costs nothing. For more than one it is wrong, and
    /// wrong in the quiet way: nothing fails at startup, sign-ins simply break for whoever lands on the wrong
    /// replica.
    ///
    /// So a host that has registered an <see cref="IKeyRingStore"/> - which is how keys are shared - is
    /// refused here rather than served: having registered one, it plainly expects sharing, and a ring that
    /// silently ignored it would be the worst of both. Use <see cref="AddKeyRing"/> with a custodian instead.
    /// </remarks>
    public static IServiceCollection AddInMemoryKeyRing(this IServiceCollection services, LocalKeys policy)
    {
        if (services.Any(descriptor => descriptor.ServiceType == typeof(IKeyRingStore)))
            throw new InvalidOperationException(
                $"{nameof(AddInMemoryKeyRing)} keeps its keys in this process only, but an "
                + $"{nameof(IKeyRingStore)} is registered, which is how keys are shared between processes. "
                + $"The store would be ignored. Use {nameof(AddKeyRing)} with a custodian to share keys, or "
                + "drop the store if a single instance is intended.");

        services.TryAddSingleton<IKeyRing>(
            serviceProvider => serviceProvider.CreateService<InMemoryKeyRing>(Dependency.Override(policy)));

        return services;
    }
}
