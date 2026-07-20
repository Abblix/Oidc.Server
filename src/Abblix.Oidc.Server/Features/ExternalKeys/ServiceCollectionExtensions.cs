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
using Abblix.Jwt;
using Abblix.Jwt.ExternalKeys;
using Abblix.Jwt.Signing;
using Abblix.Oidc.Server.Common.Interfaces;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;

namespace Abblix.Oidc.Server.Features.ExternalKeys;

/// <summary>
/// Wires an <see cref="IKeyCustodian"/> (an HSM, a cloud KMS, or a vault transit engine) into the OIDC provider
/// in two steps: WHICH custodian holds the keys, and HOW the library uses it. The Vault and Azure packages supply
/// the first; this supplies the second, so a custodian and a tier compose freely instead of multiplying into one
/// method per pair.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Opens the tier choice for a custodian already registered by the caller, which is how the packages wire a
    /// custodian that is a typed <c>HttpClient</c>. A host whose custodian needs no typed client uses
    /// <see cref="AddCustodian{TCustodian}"/> instead.
    /// </summary>
    /// <param name="services">The service collection holding the custodian registration.</param>
    /// <returns>The builder whose tier call completes the wiring.</returns>
    /// <remarks>
    /// Do not combine this with <c>AddKeyCustodian</c> from Abblix.Jwt: that is the standalone-JWT path and
    /// composes the external crypto backends itself, which the tier call here also does, and composing a family
    /// twice fails at startup. Use one path or the other.
    /// </remarks>
    public static IKeyCustodianBuilder AddCustodian(this IServiceCollection services)
    {
        // Replace, not Add: until the tier call arrives no key provider may answer, and this one throws. Replace
        // also frees THIS call from ordering (the core's default is a TryAdd, so the guard survives either way).
        // The tier call that follows is NOT order-free - see its own note.
        services.Replace(ServiceDescriptor.Singleton<IAuthServiceKeysProvider, TierNotChosenKeysProvider>());

        // Turn a missing tier call into a startup failure rather than a first-token one: the host runs the startup
        // validators before it starts the hosted service that opens the HTTP port, so the process never serves a
        // request in this state. The guard provider above stays as the second line, for a host that resolves keys
        // without a host lifetime to run this.
        services.AddOptions<CustodianTierValidation>()
            .Validate(tier => tier.ChosenTier is not null, TierNotChosenKeysProvider.Message)
            .ValidateOnStart();

        return new KeyCustodianBuilder(services);
    }

    /// <summary>
    /// Registers <typeparamref name="TCustodian"/> as the custodian and opens the tier choice. The custodian is
    /// DI-constructed, so it may depend on the host's own services.
    /// </summary>
    /// <typeparam name="TCustodian">The custodian implementation holding the private keys.</typeparam>
    /// <param name="services">The service collection to configure.</param>
    /// <returns>The builder whose tier call completes the wiring.</returns>
    public static IKeyCustodianBuilder AddCustodian<TCustodian>(this IServiceCollection services)
        where TCustodian : class, IKeyCustodian
    {
        services.TryAddSingleton<IKeyCustodian, TCustodian>();
        return services.AddCustodian();
    }

    /// <summary>
    /// Chooses the tier where the private halves NEVER enter this process: the custodian signs and unwraps, and
    /// only public halves are published at <c>/jwks</c> and used for local signature verification. Every token
    /// signed and every encrypted token consumed is a round-trip to the custodian, so throughput is bounded by it
    /// - the price of the guarantee that a compromised process yields no key.
    /// </summary>
    /// <param name="builder">The builder returned by the custodian registration.</param>
    /// <param name="keys">Names the custodian's keys to produce with, and their algorithms.</param>
    /// <returns>The service collection, for chaining.</returns>
    /// <remarks>
    /// Call this AFTER the OIDC registration (<c>AddOidcServices</c> / <c>AddOidcCore</c>). It composes the
    /// external signing and decryption backends with their in-process peers, and a composition needs those peers
    /// already registered: run first, it would find a one-member family, skip the composite, and leave the
    /// external backend to lose the singular resolve to the local one that arrives later.
    /// </remarks>
    public static IServiceCollection UseKeysInCustodian(this IKeyCustodianBuilder builder, CustodianHeldKeys keys)
        => builder.UseKeysInCustodian(_ => keys);

    /// <summary>
    /// Chooses the tier where the private halves never enter this process, resolving the key selection from the
    /// container. Suits a host whose key names come from a service (configuration, a tenant lookup); a host with
    /// literal names uses <see cref="UseKeysInCustodian(IKeyCustodianBuilder,CustodianHeldKeys)"/>. See that
    /// overload for what the tier means and when to call it.
    /// </summary>
    /// <param name="builder">The builder returned by the custodian registration.</param>
    /// <param name="keys">Resolves the key selection from the service provider, once.</param>
    /// <returns>The service collection, for chaining.</returns>
    public static IServiceCollection UseKeysInCustodian(
        this IKeyCustodianBuilder builder,
        Func<IServiceProvider, CustodianHeldKeys> keys)
    {
        var services = builder.Services;

        // Composition needs the in-process backends to compose WITH, and Compose short-circuits on a one-member
        // family: running before the OIDC registration would build no composite, and the external backend would
        // then lose the singular resolve to the local one registered after it. Nothing detects that later - the
        // seam simply reports it cannot sign a key it should have routed here - so fail where the mistake is.
        if (services.All(descriptor => descriptor.ServiceType != typeof(IDataSigner)))
            throw new InvalidOperationException(
                "Call UseKeysInCustodian after the OIDC registration (AddOidcServices / AddOidcCore). It " +
                "composes the external crypto backends with their in-process peers, and none are registered yet.");

        // Satisfies the startup validation AddCustodian armed: the wiring is now complete.
        services.Configure<CustodianTierValidation>(
            tier => tier.ChosenTier = nameof(UseKeysInCustodian));

        // The external backends belong to THIS tier rather than to the custodian: they route a private operation
        // out of process, which is precisely what this tier is. A tier that unwraps the key into memory signs with
        // the in-process backend and must not carry them on the seam.
        services.ComposeExternalKeyBackends();

        // Construct the provider through the container so the custodian is injected from DI, overriding only the
        // per-call key selection. Replaces the guard from AddCustodian, or the core's default when the host
        // registered the custodian and reached this builder by another route.
        services.Replace(ServiceDescriptor.Singleton<IAuthServiceKeysProvider>(serviceProvider =>
            serviceProvider.CreateService<ExternalKeysProvider>(Dependency.Override(keys(serviceProvider)))));

        return services;
    }

    /// <summary>
    /// Chooses the tier where the server MINTS its own keys and the custodian only protects them: each key is
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
    /// Call this AFTER the OIDC registration (<c>AddOidcServices</c> / <c>AddOidcCore</c>), for the same reason
    /// the custodian-held tier does: opening an envelope IS a custodian unwrap, so the external decryption
    /// backend has to be composed with its in-process peer, and a composition needs that peer registered first.
    /// A store must also be registered for the ring; the packages supply one.
    /// </para>
    /// </remarks>
    public static IMintedKeysBuilder UseKeysInProcess(this IKeyCustodianBuilder builder, MintedKeys policy)
    {
        var services = builder.Services;

        if (services.All(descriptor => descriptor.ServiceType != typeof(IDataSigner)))
            throw new InvalidOperationException(
                "Call UseKeysInProcess after the OIDC registration (AddOidcServices / AddOidcCore). It composes " +
                "the external crypto backends with their in-process peers, and none are registered yet.");

        // Satisfies the startup validation AddCustodian armed: the wiring is now complete.
        services.Configure<CustodianTierValidation>(tier => tier.ChosenTier = nameof(UseKeysInProcess));

        // This tier, unlike the other, needs somewhere to keep the ring, and a builder cannot force the call that
        // supplies it. Nothing else in the container reveals the omission: the ring simply fails to resolve on
        // first use, long after startup. Checking here is what the recorded tier name is for.
        services.AddOptions<CustodianTierValidation>()
            .Validate<IServiceProvider>(
                (tier, serviceProvider) =>
                    tier.ChosenTier != nameof(UseKeysInProcess) ||
                    serviceProvider.GetService<IKeyRingStore>() is not null,
                "UseKeysInProcess needs a key ring to share the keys it mints, and none is registered. Follow it " +
                "with a PersistRingTo... call from the custodian's package.")
            .ValidateOnStart();

        // Signing never reaches the custodian in this tier, but opening an envelope does: the KEK is published
        // public-only, which is exactly the signal that routes its unwrap out of process. So the external
        // backends belong on the seam here too - the decryptor carries the envelope, and the signer simply never
        // matches a minted key, since that key carries its private half and the in-process signer owns it.
        services.ComposeExternalKeyBackends();

        // The ring itself is registered by the JWT layer that owns it. What is left here is the only part that
        // is about being an OpenID Provider: pointing this server's key provider at the ring.
        var mintedKeysBuilder = services.AddKeyRing(policy);

        services.Replace(ServiceDescriptor.Singleton<IAuthServiceKeysProvider, MintedKeysProvider>());

        return mintedKeysBuilder;
    }
}
