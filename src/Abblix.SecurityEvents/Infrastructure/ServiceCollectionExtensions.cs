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
using Abblix.Jwt.ReplayPrevention;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// Wires the package into a host's service collection. Every registration lets a host
/// pre-registration win: the extension supplies defaults, never overrides.
/// </summary>
public static class ServiceCollectionExtensions
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
        ServiceDescriptor.Singleton<ISecurityEventTokenValidator, PayloadDeserializationStep>(),
    ];

    /// <summary>
    /// The default steps whose absence weakens the profile: derived from the registrations by the
    /// marker interface, never kept as a second hand-maintained list - a new critical default
    /// joins this set by being registered, not by being remembered.
    /// </summary>
    internal static readonly Type[] CriticalDefaultSteps = DefaultPipelineSteps
        .Select(descriptor => descriptor.ImplementationType!)
        .Where(type => typeof(ISecurityCriticalValidator).IsAssignableFrom(type))
        .ToArray();

    /// <summary>
    /// Declares <typeparamref name="TStep"/> as a step the profile may not lose without an allowance on record.
    /// </summary>
    /// <remarks>
    /// A package that contributes a step carrying <see cref="ISecurityCriticalValidator"/> declares it here,
    /// beside the registration that adds it. Without the declaration the marker means nothing outside this
    /// package: the guard would hold the profile only to the steps this one ships, and a step from anywhere
    /// else could be removed through the same cursor that added it, in silence.
    /// </remarks>
    /// <typeparam name="TStep">The step type, which must carry the marker to be declared at all.</typeparam>
    /// <param name="services">The <see cref="IServiceCollection"/> the step was contributed to.</param>
    /// <returns>The <see cref="IServiceCollection"/> so additional calls can be chained.</returns>
    public static IServiceCollection AddCriticalValidationStep<TStep>(this IServiceCollection services)
        where TStep : class, ISecurityCriticalValidator
        => services.AddCriticalValidationStep(typeof(TStep));

    private static IServiceCollection AddCriticalValidationStep(this IServiceCollection services, Type stepType)
    {
        services.Add(ServiceDescriptor.Singleton(new CriticalValidationStep(stepType)));
        return services;
    }

    /// <summary>
    /// Registers the security-event core: the default validation profile as a composed
    /// validator family behind the singular contract, the event registry, and the default
    /// verifier and signer over the Abblix JWT core.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The pipeline is an ordinary composed family: the ten default steps register as
    /// <see cref="ISecurityEventTokenValidator"/> implementations in execution order and
    /// collapse behind the singular contract. A consumer profile edits them in place afterwards -
    /// <c>services.Decompose&lt;ISecurityEventTokenValidator&gt;()</c> returns the live
    /// cursor with its position-aware operations - and a profile that drops or replaces a
    /// security-critical default acknowledges that through
    /// <see cref="SecurityEventsOptions.AllowInsecureValidation"/>: the guard decorating the
    /// composed result demands the acknowledgement at construction, so no door that edits the
    /// composition bypasses it. The one door outside its reach is standard container semantics:
    /// a singular <see cref="ISecurityEventTokenValidator"/> registration made after this call
    /// replaces the guarded profile wholesale (last registration wins), guard included - that is
    /// the host visibly taking ownership of validation, not an edit of this profile.
    /// </para>
    /// <para>
    /// Two of the defaults ask for more configuration before they resolve, and each fails loudly
    /// naming what is missing: the verifier needs an <see cref="IIssuerKeyResolver"/> - key trust
    /// is deployment knowledge - and the signer needs
    /// <see cref="SecurityEventsOptions.SigningKeySource"/>, which only a transmitter has. A pure
    /// receiver registers a resolver and never touches signing; a pure transmitter does the
    /// reverse.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configures the event dictionary, signing, and allowances.</param>
    public static IServiceCollection AddSecurityEvents(
        this IServiceCollection services,
        Action<SecurityEventsOptions>? configure = null)
    {
        services.AddJsonWebTokens();

        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);

        // The registry has exactly one door: SecurityEventsOptions.Events. A second registry
        // instance in the container would win the singular resolve and silently orphan every
        // registration made through the options - configuration that reads as applied and is
        // not. There is no legitimate second implementation to defer to (registrations are the
        // only thing a host customizes, and the options door carries them), so a pre-registration
        // is a wiring mistake to name, not a choice to honor.
        if (services.Any(descriptor => descriptor.ServiceType == typeof(EventTypeRegistry)))
        {
            throw new InvalidOperationException(
                $"{nameof(EventTypeRegistry)} is already registered. Register event types through "
                + $"{nameof(SecurityEventsOptions)}.{nameof(SecurityEventsOptions.Events)} in "
                + $"{nameof(AddSecurityEvents)} instead: a second registry instance would silently "
                + "orphan the registrations made there.");
        }

        services.AddSingleton<EventTypeRegistry>(
            provider => provider.GetRequiredService<IOptions<SecurityEventsOptions>>().Value.Events);

        services.TryAddSingleton<ISecurityEventTokenVerifier, DefaultSecurityEventTokenVerifier>();

        services.TryAddSingleton<ISecurityEventTokenSigner>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<SecurityEventsOptions>>().Value;

            return options.SigningKeySource is { } signingKeySource
                ? new DefaultSecurityEventTokenSigner(
                    provider.GetRequiredService<IJsonWebTokenCreator>(),
                    signingKeySource)
                : throw new InvalidOperationException(
                    $"Signing needs a key: set {nameof(SecurityEventsOptions)}."
                    + $"{nameof(SecurityEventsOptions.SigningKeySource)} in {nameof(AddSecurityEvents)}, or "
                    + $"register your own {nameof(ISecurityEventTokenSigner)}.");
        });

        // TryAddEnumerable keeps the registrations idempotent, Compose collapses the family
        // behind the singular contract, and the guard decorates the result so a weakened profile
        // cannot construct without a reasoned acknowledgement - whichever door edited it.
        services.TryAddEnumerable(DefaultPipelineSteps);

        foreach (var step in CriticalDefaultSteps)
            services.AddCriticalValidationStep(step);

        services.Compose<ISecurityEventTokenValidator, CompositeSecurityEventTokenValidator>();
        services.Decorate<ISecurityEventTokenValidator, InsecureValidationGuard>(
            Dependency.Override(ValidationProfileIdentity.Default));

        return services;
    }

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
    /// profile gives each consumer its own copy to shape, and the plain family stays whole for
    /// whoever relies on it.
    /// </para>
    /// <para>
    /// The copy is taken from the DEFAULTS, not from the current state of the plain family: a
    /// profile owner reasons from the documented baseline, and copying another consumer's edits
    /// would smuggle one profile's decisions into another depending on registration order.
    /// Critical-step accounting is per profile for the same reason - the defaults' critical steps
    /// seed the profile, <see cref="ValidationProfile.AddCriticalStep{TStep}"/> adds to it, and
    /// the guard judges each profile only by its own declarations and allowances.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="profileKey">The key the profile's validator resolves under.</param>
    /// <param name="configure">Shapes the profile: step edits, critical declarations, allowances.</param>
    /// <exception cref="InvalidOperationException">
    /// <see cref="AddSecurityEvents"/> has not run, or a profile already exists under this key -
    /// re-shaping an existing profile through a second registration would let two owners edit one
    /// copy, which is the situation profiles exist to end.
    /// </exception>
    public static IServiceCollection AddSecurityEventValidationProfile(
        this IServiceCollection services,
        object profileKey,
        Action<ValidationProfile>? configure = null)
    {
        ArgumentNullException.ThrowIfNull(profileKey);

        if (services.All(descriptor => descriptor.ServiceType != typeof(ISecurityEventTokenValidator)))
        {
            throw new InvalidOperationException(
                $"{nameof(AddSecurityEventValidationProfile)} needs the default steps to copy: call "
                + $"{nameof(AddSecurityEvents)} first.");
        }

        if (services.Any(descriptor => descriptor is { IsKeyedService: true } &&
                                       descriptor.ServiceType == typeof(ISecurityEventTokenValidator) &&
                                       Equals(descriptor.ServiceKey, profileKey)))
        {
            throw new InvalidOperationException(
                $"A validation profile already exists under '{profileKey}'. A profile has one owner; "
                + "a second registration under the same key would let two owners edit one copy.");
        }

        foreach (var step in DefaultPipelineSteps)
        {
            services.Add(ServiceDescriptor.DescribeKeyed(
                typeof(ISecurityEventTokenValidator), profileKey, step.ImplementationType!, step.Lifetime));
        }

        foreach (var critical in CriticalDefaultSteps)
        {
            services.Add(ServiceDescriptor.KeyedSingleton(
                profileKey, (_, _) => new CriticalValidationStep(critical)));
        }

        services.ComposeKeyed<ISecurityEventTokenValidator, CompositeSecurityEventTokenValidator>(profileKey);

        var profile = new ValidationProfile(services, profileKey);
        configure?.Invoke(profile);

        // Decorated AFTER configure so the identity carries the profile's recorded allowances.
        // The guard itself still judges the final composition at first resolve, so later cursor
        // edits stay inside its reach.
        services.DecorateKeyed<ISecurityEventTokenValidator, InsecureValidationGuard>(
            profileKey, Dependency.Override(profile.ToIdentity()));

        return services;
    }

    /// <summary>
    /// Registers JWKS-based key resolution as the <see cref="IIssuerKeyResolver"/>: issuers'
    /// keys fetched from their published JWK Set documents and cached, with a forced refetch
    /// when a token names a key the cache has never seen.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">
    /// Where key sets live and how long they answer from cache; a Shared Signals receiver sets
    /// the URI selector from the transmitter's advertised "jwks_uri".</param>
    public static IServiceCollection AddJwksKeyResolution(
        this IServiceCollection services,
        Action<JwksKeyResolutionOptions>? configure = null)
    {
        services.AddHttpClient();

        if (configure is not null)
        {
            services.Configure(configure);
        }

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IIssuerKeyResolver, JwksIssuerKeyResolver>();

        return services;
    }

    /// <summary>
    /// Registers the replay cache over the host's <c>IDistributedCache</c> as the
    /// <see cref="IReplayCache"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The store itself is the host's choice and is deliberately not registered here:
    /// <c>AddDistributedMemoryCache()</c> gives a single-instance receiver process-local
    /// behavior, Redis or another backend gives a scaled-out one a shared memory - the same
    /// registration either way.
    /// </para>
    /// <para>
    /// How long an identifier is remembered comes from the validation profile rather than from
    /// here, because the retention only makes sense against the freshness window it has to
    /// outlive - see <see cref="SecurityEventTokenValidationOptions.ReplayRetention"/>. The
    /// contract itself lives in Abblix.JWT, so a host that also runs the OpenID Connect server
    /// shares one replay store between its DPoP proofs, its client assertions and its events.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddDistributedReplayCache(this IServiceCollection services)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IReplayCache>(
            provider => provider.CreateService<DistributedReplayCache>(
                Dependency.Override(CacheKeyPrefix)));

        return services;
    }

    /// <summary>
    /// Keeps these entries out of the way of whatever else shares the host's cache. A stable
    /// literal: entries written under one prefix are unreachable under another, so a rolling
    /// upgrade that changed it would run without replay protection until they aged out.
    /// </summary>
    private const string CacheKeyPrefix = "Abblix.SecurityEvents:ReplayPrevention:";

}
