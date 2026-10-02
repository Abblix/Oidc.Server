// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// Wires named validation profiles: each consumer of security event tokens owns its own copy of
/// the step family, shaped without touching any other.
/// </summary>
public static class ValidationProfileServiceCollectionExtensions
{
    /// <summary>
    /// The default receiver profile, in its required order: parse, then the cheap unverified
    /// rejections, then the signature, then the checks that read trusted claims.
    /// </summary>
    private static readonly ServiceDescriptor[] DefaultPipelineSteps =
    [
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, ParseStep>(),
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, TypHeaderStep>(),
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, ExpAbsenceStep>(),
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, EventsPresenceStep>(),
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, JwtIdPresenceStep>(),
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, IssuerAllowlistStep>(),
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, SignatureStep>(),
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, AudienceStep>(),
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, IssuedAtWindowStep>(),
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, TimeOfEventStep>(),
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, PayloadDeserializationStep>(),
    ];

    /// <summary>
    /// The default steps whose absence weakens the profile: derived from the registrations by the
    /// marker interface, never kept as a second hand-maintained list - a new critical default
    /// joins this set by being registered, not by being remembered.
    /// </summary>
    private static readonly Type[] CriticalDefaultSteps = DefaultPipelineSteps
        .Select(descriptor => descriptor.ImplementationType!)
        .Where(type => typeof(ISecurityCriticalValidator).IsAssignableFrom(type))
        .ToArray();

    /// <summary>
    /// Creates a NAMED validation profile: a keyed copy of the default step family that
    /// <paramref name="configure"/> edits without touching any other profile, resolvable as a
    /// keyed <see cref="ISecurityEventTokenValidator"/> under <paramref name="profileKey"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This exists for the host whose consumers contradict each other. One composed family per
    /// host was enough until two token kinds met in one container: Back-Channel Logout REQUIRES
    /// <c>exp</c> and pins <c>typ</c> to its own value, a Shared Signals SET forbids the former
    /// and pins the latter differently - so whichever consumer edits the shared family breaks the
    /// other, and the breakage surfaces as every token of the other kind being refused. A named
    /// profile gives each consumer its own copy to shape - and no unnamed shared family exists
    /// to collide over at all.
    /// </para>
    /// <para>
    /// The copy is taken from the documented DEFAULTS, so a profile owner reasons from the
    /// baseline and no other consumer's decisions can reach it through registration order.
    /// Critical-step accounting is per profile for the same reason - the defaults' critical steps
    /// seed the profile, <see cref="ValidationProfile.AddCriticalStep{TStep}"/> adds to it, and
    /// the guard judges each profile only by its own declarations and allowances.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="profileKey">The key the profile's validator resolves under.</param>
    /// <param name="configure">Shapes the profile: step edits, critical declarations, allowances.</param>
    /// <exception cref="InvalidOperationException">
    /// <see cref="ServiceCollectionExtensions.AddSecurityEvents"/> has not run, or a profile already
    /// exists under this key - re-shaping an existing profile through a second registration would
    /// let two owners edit one copy, which is the situation profiles exist to end.
    /// </exception>
    public static IServiceCollection AddSecurityEventValidationProfile(
        this IServiceCollection services,
        object profileKey,
        Action<ValidationProfile>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(profileKey);

        if (services.All(descriptor => descriptor.ServiceType != typeof(EventTypeRegistry)))
        {
            throw new InvalidOperationException(
                $"{nameof(AddSecurityEventValidationProfile)} builds on the security-event core: call "
                + $"{nameof(ServiceCollectionExtensions.AddSecurityEvents)} first.");
        }

        if (services.Any(descriptor => descriptor is { IsKeyedService: true } &&
                                       descriptor.ServiceType == typeof(ISecurityEventTokenValidator) &&
                                       Equals(descriptor.ServiceKey, profileKey)))
        {
            throw new InvalidOperationException(
                $"A validation profile already exists under '{profileKey}'. A profile has one owner; "
                + "a second registration under the same key would let two owners edit one copy.");
        }

        // No steps are laid down here. A profile states its own pipeline, in order, so the order a
        // token is judged in is readable where it is decided rather than being a baseline the
        // reader must know plus the edits made to it. What IS laid down is the expectation below:
        // the security-critical defaults, which the guard then demands of whatever the profile
        // turned out to contain.
        //
        // The two halves are deliberately independent. Seeding the pipeline as well would make a
        // future critical default arrive in every profile silently, including profiles designed
        // before it existed and possibly broken by it; seeding only the expectation makes the same
        // addition surface as "this profile does not carry it - allow it or add it", which is a
        // decision its owner takes rather than a change nobody reviewed.
        foreach (var critical in CriticalDefaultSteps)
        {
            services.Add(ServiceDescriptor.KeyedSingleton(
                profileKey, (_, _) => new CriticalValidationStep(critical)));
        }

        // Composition happens after the profile is shaped, not before it: it gathers the members
        // registered under this key, so calling it first would gather nothing. That is not an
        // error it reports - composing an empty family is a no-op - so the profile would end up
        // with no validator at all and the failure would surface far from here.
        var profile = new ValidationProfile(services, profileKey);
        configure?.Invoke(profile);

        // Refuses a profile that listed nothing, which is where the no-op above would surface.
        profile.EnsureComposed();

        // Decorated AFTER configure so the identity carries the profile's recorded allowances.
        // The guard itself still judges the final composition at first resolve, so later cursor
        // edits stay inside its reach.
        services.DecorateKeyed<ISecurityEventTokenValidator, InsecureValidationGuard>(
            profileKey, Dependency.Override(profile.ToIdentity()));

        return services;
    }

    /// <summary>
    /// Lays down the documented default pipeline, in its required order: parse, then the cheap
    /// unverified rejections, then the signature, then the checks that read trusted claims.
    /// </summary>
    /// <remarks>
    /// For a profile that wants the baseline and departs from it by editing - the shape most
    /// consumers of a plain SET want. A profile that judges a different KIND of token lists its own
    /// steps instead, because the departures are then the point rather than the exception, and a
    /// reader should not have to hold this order in mind to know what that profile does.
    /// </remarks>
    /// <param name="profile">The profile being shaped.</param>
    public static ValidationProfile UseDefaultPipeline(this ValidationProfile profile)
    {
        ArgumentNullException.ThrowIfNull(profile);

        foreach (var step in DefaultPipelineSteps)
            profile.UseStep(step.ImplementationType!, step.Lifetime);

        return profile;
    }

    /// <summary>
    /// Creates a named validation profile, and only on first sight of its key.
    /// </summary>
    /// <remarks>
    /// A consumer's registration must survive being run twice without doubling its profile. What
    /// it must NOT survive is somebody else having taken the key first: that is the collision
    /// named profiles exist to end, and the loser sees every one of its tokens refused by a
    /// pipeline shaped for another kind.
    /// <para>
    /// Those two cases look identical from the key alone - a profile is there either way - so this
    /// leaves a marker of its own and reads that instead. A second call by the same registration
    /// finds its marker and does nothing; a foreign profile under the same key leaves no marker,
    /// so the strict registration runs and refuses loudly, naming the key.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="profileKey">The key the profile's validator resolves under.</param>
    /// <param name="configure">Shapes the profile: its steps, critical declarations, allowances.</param>
    public static IServiceCollection AddSecurityEventValidationProfileOnce(
        this IServiceCollection services,
        string profileKey,
        Action<ValidationProfile> configure)
    {
        ArgumentNullException.ThrowIfNull(profileKey);

        var marker = new ProfileCreatedMarker(profileKey);
        if (services.Any(descriptor => Equals(descriptor.ImplementationInstance, marker)))
            return services;

        services.AddSecurityEventValidationProfile(profileKey, configure);
        services.AddSingleton(marker);

        return services;
    }

    /// <summary>
    /// The record that THIS registration created the profile under a key, as opposed to the key
    /// merely being taken.
    /// </summary>
    /// <param name="ProfileKey">The key whose profile was created here.</param>
    private sealed record ProfileCreatedMarker(string ProfileKey);
}
