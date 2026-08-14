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
/// A profile is a keyed copy of the default family that one consumer owns outright: it edits its
/// copy, declares its own critical steps, records its own allowances, and resolves its validator by
/// its key, while every other profile - the plain default included - stays exactly as its owner
/// composed it.
/// </remarks>
public sealed class ValidationProfile
{
    private readonly IServiceCollection _services;
    private readonly List<string> _allowances = [];

    internal ValidationProfile(IServiceCollection services, object profileKey)
    {
        _services = services;
        Key = profileKey;
        Steps = services.DecomposeKeyed<ISecurityEventTokenValidator>(profileKey);
    }

    /// <summary>The key this profile's validator resolves under.</summary>
    public object Key { get; }

    /// <summary>
    /// The live cursor over this profile's steps, in execution order. Plain descriptors are
    /// accepted - the cursor keys them to this profile on insert - and edits here touch no other
    /// profile.
    /// </summary>
    public IComposition<ISecurityEventTokenValidator> Steps { get; }

    /// <summary>
    /// Declares <typeparamref name="TStep"/> as a step THIS profile may not lose without an
    /// allowance on record - the profile-scoped sibling of
    /// <see cref="ServiceCollectionExtensions.AddCriticalValidationStep{TStep}"/>.
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
    /// Acknowledges that this profile drops or replaces a security-critical step, and why - the
    /// profile-scoped sibling of <see cref="SecurityEventsOptions.AllowInsecureValidation"/>.
    /// </summary>
    public ValidationProfile AllowInsecureValidation(string reason)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(reason);
        _allowances.Add(reason);
        return this;
    }

    /// <summary>The identity the guard judges this profile by, frozen at registration time.</summary>
    internal ValidationProfileIdentity ToIdentity() => new(Key, _allowances);
}

/// <summary>
/// What the <see cref="InsecureValidationGuard"/> needs to know about the profile it decorates:
/// which family to read and which allowances excuse a missing critical step.
/// </summary>
/// <param name="Key">The profile's service key, or null for the plain default profile.</param>
/// <param name="Allowances">
/// The profile's own allowances, or null for the default profile - whose allowances live in
/// <see cref="SecurityEventsOptions"/> and are read from options at construction, because that is
/// where its owners have always recorded them.
/// </param>
internal sealed record ValidationProfileIdentity(object? Key, IReadOnlyList<string>? Allowances)
{
    /// <summary>The plain default profile: the unkeyed family, allowances from options.</summary>
    public static readonly ValidationProfileIdentity Default = new(Key: null, Allowances: null);
}
