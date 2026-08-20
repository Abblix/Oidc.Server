// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Abblix.SecurityEvents.Validation;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// One named validation profile under construction: the editing surface
/// <see cref="ServiceCollectionExtensions.AddSecurityEventValidationProfile"/> hands to its
/// configure delegate.
/// </summary>
/// <remarks>
/// A profile exists because two consumers of security event tokens in one host can demand
/// CONTRADICTORY things of the same claim - Back-Channel Logout requires <c>exp</c> where a Shared
/// Signals SET forbids it, and each pins its own <c>typ</c> - so no single pipeline can serve both.
/// A profile is a keyed family one consumer owns outright: it lists its own steps in the order they
/// judge a token, declares its own critical steps, records its own allowances, and resolves its
/// validator by its key, while every other profile stays exactly as its owner composed it. There is
/// no unnamed profile to fall back to: naming is what makes ownership visible.
/// </remarks>
public sealed class ValidationProfile
{
    private readonly IServiceCollection _services;
    private readonly List<ValidationAllowance> _allowances = [];

    private IComposition<ISecurityEventTokenValidator>? _steps;

    internal ValidationProfile(IServiceCollection services, object profileKey)
    {
        _services = services;
        Key = profileKey;
    }

    /// <summary>The key this profile's validator resolves under.</summary>
    public object Key { get; }

    /// <summary>
    /// The live cursor over this profile's steps, in execution order. Plain descriptors are
    /// accepted - the cursor keys them to this profile on insert - and edits here touch no other
    /// profile.
    /// </summary>
    /// <remarks>
    /// Reading this composes the profile, which is why it is a property with a body rather than
    /// one assigned in the constructor: a cursor is a view of a composed family, and a profile is
    /// composed once it has stopped being listed. Listing through <see cref="Use{TStep}"/> before
    /// the first read is therefore ordinary, and editing after it is ordinary too - what cannot
    /// happen is composing an empty family, since composition of nothing is a no-op that would
    /// leave the profile with no validator at all.
    /// </remarks>
    public IComposition<ISecurityEventTokenValidator> Steps => _steps ??= Compose();

    /// <summary>
    /// Composes this profile's listed steps into its validator, if that has not happened yet.
    /// </summary>
    /// <remarks>
    /// Called by the registration once the profile has been shaped. Reading <see cref="Steps"/>
    /// does the same, whichever comes first.
    /// </remarks>
    internal void EnsureComposed() => _steps ??= Compose();

    /// <summary>
    /// Turns the listed steps into the composed family this profile's validator is.
    /// </summary>
    /// <exception cref="InvalidOperationException">Nothing was listed.</exception>
    private IComposition<ISecurityEventTokenValidator> Compose()
    {
        // Composition of an empty family is a NO-OP, not an error: it would leave no composite
        // behind, so this profile would have no validator, and a cursor taken over it would be a
        // view of nothing through which every later edit would land nowhere. Both failures are
        // silent, and both are this one condition, so it is named here once.
        if (_services.All(descriptor => !(descriptor is { IsKeyedService: true }
                                          && descriptor.ServiceType == typeof(ISecurityEventTokenValidator)
                                          && Equals(descriptor.ServiceKey, Key))))
        {
            throw new InvalidOperationException(
                $"The validation profile '{Key}' lists no steps, so it would have no validator at all. "
                + $"List its pipeline with {nameof(Use)}, or take the documented default order with "
                + $"{nameof(ServiceCollectionExtensions.UseDefaultPipeline)}.");
        }

        _services.ComposeKeyed<ISecurityEventTokenValidator, CompositeSecurityEventTokenValidator>(Key);
        return _services.DecomposeKeyed<ISecurityEventTokenValidator>(Key);
    }

    /// <summary>
    /// Appends <typeparamref name="TStep"/> to the end of this profile's pipeline.
    /// </summary>
    /// <remarks>
    /// A profile states its pipeline by listing it, so the order a token is judged in is the order
    /// written here rather than a baseline the reader has to know plus the edits made to it. The
    /// list is not what makes a profile safe - the guard does that, by demanding an allowance for
    /// every security-critical default the list leaves out - so leaving one out is a decision that
    /// has to be written down, whether it was made deliberately or by forgetting.
    /// </remarks>
    public ValidationProfile Use<TStep>()
        where TStep : class, ISecurityEventTokenValidator
    {
        UseStep(typeof(TStep), ServiceLifetime.Singleton);
        return this;
    }

    /// <summary>
    /// Appends one step as a member keyed to this profile.
    /// </summary>
    /// <remarks>
    /// Written against the service collection rather than through <see cref="Steps"/>, which is
    /// what lays a pipeline down: the cursor is for EDITING an existing family and reads it to
    /// place each edit, while listing a pipeline has nothing to read yet.
    /// </remarks>
    internal void UseStep(Type stepType, ServiceLifetime lifetime)
    {
        var descriptor = ServiceDescriptor.DescribeKeyed(
            typeof(ISecurityEventTokenValidator), Key, stepType, lifetime);

        // Before composition the family IS the set of descriptors under this key, so the step is
        // simply one of them. Afterwards that key belongs to the composite, and a descriptor added
        // beside it would not be a member but a rival answer to the same question - so a late
        // listing goes through the cursor, which knows where members live.
        if (_steps is { } composed)
            composed.AddLast(descriptor);
        else
            _services.Add(descriptor);
    }

    /// <summary>
    /// Declares <typeparamref name="TStep"/> as a step THIS profile may not lose without an
    /// allowance on record.
    /// </summary>
    /// <remarks>
    /// Scoped rather than global on purpose: a package's step is critical for the profile that
    /// carries it, and a global declaration would make every OTHER profile's guard demand a step
    /// that was never meant for it.
    /// </remarks>
    public ValidationProfile AddCriticalStep<TStep>()
        where TStep : class, ISecurityCriticalValidator
    {
        _services.Add(ServiceDescriptor.KeyedSingleton(Key, (_, _) => new CriticalValidationStep(typeof(TStep))));
        return this;
    }

    /// <summary>
    /// Acknowledges that this profile drops or replaces <typeparamref name="TStep"/>, a
    /// security-critical default, and why. The guard logs every allowance at first resolve, so the
    /// weakening stays visible in the boot log.
    /// </summary>
    /// <remarks>
    /// The allowance names the step it excuses, and excuses only that one. An allowance that
    /// excused "some critical step" would excuse every future one too: a profile carrying two
    /// reasoned departures would silently absorb a third, added to the core long after anyone read
    /// this profile - and the third could be the step that keeps an attacker-named issuer from
    /// deciding which keys are fetched.
    /// </remarks>
    /// <typeparam name="TStep">The security-critical default this profile does not carry.</typeparam>
    /// <param name="reason">Why this profile is right not to carry it.</param>
    public ValidationProfile AllowInsecureValidation<TStep>(string reason)
        where TStep : class, ISecurityEventTokenValidator
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        _allowances.Add(new ValidationAllowance(typeof(TStep), reason));
        return this;
    }

    /// <summary>The identity the guard judges this profile by, frozen at registration time.</summary>
    internal ValidationProfileIdentity ToIdentity() => new(Key, _allowances);
}
