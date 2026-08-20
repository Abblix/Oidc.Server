// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0


using Abblix.DependencyInjection;
using Abblix.Jwt.Signing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Abblix.Jwt.ExternalKeys;

/// <summary>
/// Wires an <see cref="IKeyCustodian"/> (an HSM, a cloud KMS, or a vault transit engine) in two steps: WHICH
/// custodian holds the keys, and HOW the library uses it. The backend packages supply the first; the placement
/// calls here supply the second, so a custodian and a placement compose freely instead of multiplying into one
/// method per pair.
/// </summary>
/// <remarks>
/// Both halves live in this package because both are about key material and neither is about any particular
/// consumer of it. Whoever consumes the keys - an OpenID Provider publishing them at its JWKS endpoint, a
/// transmitter signing security event tokens, a client protecting its own state - reads the recorded
/// <see cref="KeyPlacement"/> and needs no registration call of its own.
/// </remarks>
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
    /// Registers <typeparamref name="TCustodian"/> as the custodian and opens the placement choice. The custodian is
    /// DI-constructed, so it may depend on the host's own services. A host whose custodian is already registered -
    /// a typed <c>HttpClient</c>, or an instance it built itself - calls <see cref="RequireKeyPlacement"/> instead.
    /// </summary>
    /// <typeparam name="TCustodian">The custodian implementation holding the private keys.</typeparam>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The builder whose placement call completes the wiring.</returns>
    /// <remarks>
    /// Do not combine this with <c>ComposeExternalKeyBackends</c>: the placement call performs that itself, and
    /// <c>Compose</c> refuses the second composition on the spot, at the registration call rather than at
    /// startup. Use this path, or that one, never both.
    /// </remarks>
    public static IKeyCustodianBuilder AddCustodian<TCustodian>(this IServiceCollection services)
        where TCustodian : class, IKeyCustodian
    {
        services.TryAddSingleton<IKeyCustodian, TCustodian>();
        return services.RequireKeyPlacement();
    }

    /// <summary>
    /// Keeps the private halves OUT of this process entirely: the custodian signs and unwraps, and only public
    /// halves are published and used for local signature verification. Every token signed and every encrypted token
    /// consumed is a round-trip to the custodian, so throughput is bounded by it - the price of the guarantee that
    /// a compromised process yields no key.
    /// </summary>
    /// <param name="builder">The builder returned by the custodian registration.</param>
    /// <param name="keys">Names the custodian's keys to produce with, and their algorithms.</param>
    /// <returns>The service collection, for chaining.</returns>
    /// <remarks>
    /// Call this AFTER <see cref="ServiceCollectionExtensions.AddJsonWebTokens"/>. It composes the external signing
    /// and decryption backends with their in-process peers, and a composition needs those peers already registered:
    /// run first, it would find a one-member family, skip the composite, and leave the external backend to lose the
    /// singular resolve to the local one that arrives later.
    /// </remarks>
    public static IServiceCollection UseKeysInCustodian(this IKeyCustodianBuilder builder, CustodianHeldKeys keys)
    {
        var services = ChoosePlacement(builder, KeyPlacement.Custodian, nameof(UseKeysInCustodian));

        // Replace rather than Add: this argument IS the host's key selection, so exactly one selection lives in
        // the collection, ahead of anything the host registered earlier.
        services.Replace(ServiceDescriptor.Singleton(keys));
        return services;
    }

    /// <summary>
    /// Keeps the private halves out of this process, reading the key selection from a service instead of a literal.
    /// Suits a host whose key names come from its configuration; a host with literal names uses
    /// <see cref="UseKeysInCustodian(IKeyCustodianBuilder,CustodianHeldKeys)"/>. See that overload for what this
    /// placement means and when to call it.
    /// </summary>
    /// <param name="builder">The builder returned by the custodian registration.</param>
    /// <param name="keys">Resolves the key selection from the service provider, once.</param>
    /// <returns>The service collection, for chaining.</returns>
    /// <remarks>
    /// The selection is a singleton, so the factory runs once per container and the answer is fixed for the life of
    /// the process. That rules out anything varying per request or per tenant: a host needing that registers its own
    /// key provider rather than varying this.
    /// </remarks>
    public static IServiceCollection UseKeysInCustodian(
        this IKeyCustodianBuilder builder,
        Func<IServiceProvider, CustodianHeldKeys> keys)
    {
        var services = ChoosePlacement(builder, KeyPlacement.Custodian, nameof(UseKeysInCustodian));

        // Replace, for the reason the sibling overload gives: this argument IS the host's key selection. Note the
        // registered service type is CustodianHeldKeys, not the delegate - overload resolution prefers the factory
        // overload here, so both overloads leave the collection in the same shape.
        services.Replace(ServiceDescriptor.Singleton(keys));
        return services;
    }

    /// <summary>
    /// Chooses the placement where the library MINTS its own keys and the custodian only protects them: each key is
    /// generated in process, encrypted to the custodian's key-encryption key, shared as ciphertext through
    /// <see cref="IKeyRingStore"/>, and rotated on the policy's schedule. Signing then runs in process, so the
    /// custodian is touched once per key rather than once per token.
    /// </summary>
    /// <param name="builder">The builder returned by the custodian registration.</param>
    /// <param name="policy">What to mint, how often, and which key seals it.</param>
    /// <returns>The builder whose <c>PersistRingTo...</c> call says where the ring lives.</returns>
    /// <remarks>
    /// This is the weaker posture of the two, which is why it is named rather than defaulted: the private half is
    /// unwrapped into process memory and stays there, so a compromised process yields the key itself, not merely
    /// the ability to ask the custodian to sign while its credential lives. Use
    /// <see cref="UseKeysInCustodian(IKeyCustodianBuilder,CustodianHeldKeys)"/> when the key must never be in
    /// memory at all.
    /// <para>
    /// Call this AFTER <see cref="ServiceCollectionExtensions.AddJsonWebTokens"/>, for the same reason the
    /// custodian-held placement does: opening an envelope IS a custodian unwrap, so the external decryption backend
    /// has to be composed with its in-process peer, and a composition needs that peer registered first. A store
    /// must also be registered for the ring; the backend packages supply one.
    /// </para>
    /// </remarks>
    public static IMintedKeysBuilder UseKeysInProcess(this IKeyCustodianBuilder builder, MintedKeys policy)
    {
        var services = ChoosePlacement(builder, KeyPlacement.InProcess, nameof(UseKeysInProcess));

        // This placement, unlike the other, needs somewhere to keep the ring, and a builder cannot force the call
        // that supplies it. Nothing else in the container reveals the omission: the ring simply fails to resolve on
        // first use, long after startup. Checking here is what the recorded placement is for.
        services.AddOptions<KeyPlacementChoice>()
            .Validate<IServiceProvider>(
                (choice, serviceProvider) =>
                    choice.ChosenPlacement != KeyPlacement.InProcess ||
                    serviceProvider.GetService<IKeyRingStore>() is not null,
                $"{nameof(UseKeysInProcess)} needs an {nameof(IKeyRingStore)} to share the keys it mints, and none "
                + "is registered. Follow it with a PersistRingTo... call from the custodian's package.");

        return services.AddKeyRing(policy);
    }

    /// <summary>
    /// The half both placements share: refuse an ordering that would compose nothing, record the choice, and put
    /// the external backends on the crypto seams.
    /// </summary>
    /// <remarks>
    /// The external backends belong to the PLACEMENT rather than to the custodian, because they route a private
    /// operation out of process, which is what a placement decides. Both placements need them: the minting one
    /// signs locally but still opens each sealed key through the custodian, and that unwrap is external.
    /// </remarks>
    private static IServiceCollection ChoosePlacement(
        IKeyCustodianBuilder builder,
        KeyPlacement placement,
        string placementCall)
    {
        var services = builder.Services;

        // Composition needs the in-process backends to compose WITH, and Compose short-circuits on a one-member
        // family: running before the JWT registration would build no composite, and the external backend would then
        // lose the singular resolve to the local one registered after it. Nothing detects that later - the seam
        // simply reports it cannot sign a key it should have routed here - so fail where the mistake is.
        //
        // Only AddJsonWebTokens is named. Whichever registration the host wrote performs it (an OpenID Provider's
        // does, and so does the security-event one), and naming those here would be a literal for a method in an
        // assembly this one does not reference: nothing would keep it true through a rename, and it would advise a
        // host that has no such method to call it.
        if (services.All(descriptor => descriptor.ServiceType != typeof(IDataSigner)))
            throw new InvalidOperationException(
                $"Call {placementCall} after {nameof(ServiceCollectionExtensions.AddJsonWebTokens)}, which every "
                + "registration that adds JSON Web Token services performs. It composes the external crypto "
                + "backends with their in-process peers, and none are registered yet.");

        // A placement says where a CUSTODIAN's keys live, so one without a custodian is half a sentence. It
        // would otherwise pass every guard here and at startup - the placement is recorded, so the choice looks
        // made - and surface on the first key operation as the container's own "unable to resolve IKeyCustodian",
        // which names neither this call nor the registration that is missing.
        var custodian = services.LastOrDefault(descriptor => descriptor.ServiceType == typeof(IKeyCustodian))
            ?? throw new InvalidOperationException(
                $"{placementCall} says where a key custodian's private keys live, but no {nameof(IKeyCustodian)} "
                + $"is registered. Register one first - {nameof(AddCustodian)} does it, as does each backend "
                + "package's own AddVaultCustodian or AddAzureCustodian.");

        // The backends that route a private operation out of process are singletons, so a custodian shorter-lived
        // than they are is a captive dependency. It would be caught by ValidateScopes in Development and by nothing
        // at all in Production, where the first resolve pins one scope's custodian for the process lifetime.
        if (custodian.Lifetime != ServiceLifetime.Singleton)
            throw new InvalidOperationException(
                $"{nameof(IKeyCustodian)} is registered as {custodian.Lifetime} and must be a "
                + $"{ServiceLifetime.Singleton}: the signing and decryption backends that reach it are singletons, "
                + "so a shorter lifetime would pin one scope's custodian for the life of the process.");

        // Satisfies the startup validation the custodian registration armed: the wiring is now complete.
        services.Configure<KeyPlacementChoice>(choice => choice.ChosenPlacement = placement);

        services.ComposeExternalKeyBackends();
        return services;
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

        // Both the ring and the loop that keeps it current read the clock, and this package is consumable without
        // the registrations that would otherwise have supplied one. TryAdd, so a host's own clock still wins.
        services.TryAddSingleton(TimeProvider.System);

        var builder = new MintedKeysBuilder(services, policy);

        // CreateService, unlike the plain registrations around it, because the policy is a per-call value the
        // container knows nothing about: everything else the ring needs is resolved normally. It is read off the
        // builder rather than captured, so a call chained after this one - AdoptExistingKeys - still reaches the
        // ring: this factory runs when the container builds, by which time the whole chain has run.
        services.TryAddSingleton(
            serviceProvider => serviceProvider.CreateService<KeyRing>(Dependency.Override(builder.Policy)));

        // The concrete type is what is constructed, and the contract is an alias to it. Registering the contract
        // with its own factory instead would build a SECOND ring: the refresh service would keep one current
        // while every consumer read the other, which fails as a server publishing keys it never rotates.
        services.TryAddSingleton<IKeyRing>(serviceProvider => serviceProvider.GetRequiredService<KeyRing>());

        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, KeyRingRefreshService>());

        return builder;
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

        // The ring reads the clock, and this package is consumable without the registrations that would otherwise
        // have supplied one.
        services.TryAddSingleton(TimeProvider.System);

        services.TryAddSingleton<IKeyRing>(
            serviceProvider => serviceProvider.CreateService<InMemoryKeyRing>(Dependency.Override(policy)));

        return services;
    }
}
