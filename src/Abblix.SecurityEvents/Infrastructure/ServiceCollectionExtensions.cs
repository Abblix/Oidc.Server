// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.DependencyInjection;
using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.BackChannelLogout;
using Abblix.SecurityEvents.BackChannelLogout.Steps;
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
    private static readonly Type[] CriticalDefaultSteps = DefaultPipelineSteps
        .Select(descriptor => descriptor.ImplementationType!)
        .Where(type => typeof(ISecurityCriticalValidator).IsAssignableFrom(type))
        .ToArray();

    /// <summary>
    /// Registers the security-event core: the event registry and the default verifier and
    /// signer over the Abblix JWT core. Validation is NOT wired here - each consumer creates
    /// its own named profile with <see cref="AddSecurityEventValidationProfile"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This call registers NO validator: validation lives in named profiles, each created by
    /// <see cref="AddSecurityEventValidationProfile"/> from the documented default steps and
    /// owned by the one consumer that names it. There is deliberately no unnamed shared family.
    /// It existed once, and it is the shape that produced the collision this API replaces: two
    /// consumers of security event tokens in one host shaped one family to contradictory demands,
    /// the outcome depended on registration order, and the loser saw every one of its tokens
    /// refused. An unnamed family invites exactly that consumer back - each editor believes the
    /// shared copy is its own - so the ceremony of naming a profile is the point, not a cost.
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
    /// <param name="configure">Configures the event dictionary and signing.</param>
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

        services.TryAddSingleton<ISecurityEventTokenVerifier>(provider => new DefaultSecurityEventTokenVerifier(
            provider.GetRequiredService<IJsonWebTokenValidator>(),
            provider.GetRequiredService<IIssuerKeyResolver>(),
            provider.GetRequiredService<IOptions<SecurityEventsOptions>>().Value.EffectiveSigningAlgorithms));

        services.TryAddSingleton<ISecurityEventTokenSigner>(provider =>
        {
            var options = provider.GetRequiredService<IOptions<SecurityEventsOptions>>().Value;

            return options.SigningKeySource is { } signingKeySource
                ? new DefaultSecurityEventTokenSigner(
                    provider.GetRequiredService<IJsonWebTokenCreator>(),
                    signingKeySource,
                    options.EffectiveSigningAlgorithms)
                : throw new InvalidOperationException(
                    $"Signing needs a key: set {nameof(SecurityEventsOptions)}."
                    + $"{nameof(SecurityEventsOptions.SigningKeySource)} in {nameof(AddSecurityEvents)}, or "
                    + $"register your own {nameof(ISecurityEventTokenSigner)}.");
        });

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

        if (services.All(descriptor => descriptor.ServiceType != typeof(EventTypeRegistry)))
        {
            throw new InvalidOperationException(
                $"{nameof(AddSecurityEventValidationProfile)} builds on the security-event core: call "
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

    /// <summary>
    /// Registers the receiver of Logout Tokens a provider posts to this application
    /// (OpenID Connect Back-Channel Logout 1.0 Section 2.6), as its own named validation profile.
    /// </summary>
    /// <remarks>
    /// <para>
    /// A Logout Token is a security event token whose profile contradicts the security-event
    /// default on two points, which is what a named profile is for: the default forbids <c>exp</c>
    /// where Section 2.6 requires it, and pins the SET's own type where Section 4.1 forbids
    /// requiring any. Both departures go through the reasoned allowance door, so a host reading
    /// its boot log sees which critical defaults this profile does not carry and why.
    /// </para>
    /// <para>
    /// It sits in this package rather than beside Shared Signals because a logout notification has
    /// no stream: one token, delivered once, from a provider the application already knows. What
    /// it uses is the token and the pipeline, both of which are here.
    /// </para>
    /// <para>
    /// Registering this is the whole opt-in: an application that does not call it has nothing that
    /// accepts a Logout Token. The host still owes two registrations of its own: an
    /// <see cref="ILogoutNotificationSink"/>, because Section 2.7 makes locating and clearing the
    /// sessions the RP's and only the RP knows where it keeps them, and key resolution (for
    /// example <see cref="AddJwksKeyResolution"/>), because key trust is deployment knowledge. The
    /// request and the response themselves are this package's:
    /// <see cref="BackChannelLogoutHandler"/> reads the posted form and shapes the answer, leaving
    /// a host adapter nothing to decide but how to render it.
    /// </para>
    /// <para>
    /// Step 8, the replay check, is optional in the specification and taken up here, because the
    /// request carrying the token is unauthenticated and the token is a bearer credential in the
    /// plainest sense. The default cache rides the host's <c>IDistributedCache</c>; a deployment
    /// wanting a strictly atomic reservation derives a <c>ReplayCacheBase</c> over its own
    /// store's conditional write and registers that, which TryAdd here then leaves alone.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="options">
    /// What this receiver expects of every Logout Token: the provider as the issuer and this
    /// application's client identifier as the audience. Registered as the shared instance, so a
    /// host pre-registering its own wins.</param>
    public static IServiceCollection AddBackChannelLogoutReceiver(
        this IServiceCollection services,
        BackChannelLogoutValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);

        // First, so a host that forgot the core is told so before anything is registered: the
        // profile registration is what names the missing call.
        services.AddSecurityEventValidationProfileOnce(ValidationProfileKeys.LogoutToken, profile =>
        {
            // The whole order a Logout Token is judged in. Two steps stand where the SET defaults
            // put their own and answer the opposite question - the type rule of Section 4.1, the
            // expiry of Section 2.6 - and three are this kind's alone. Written out rather than as
            // edits to the SET order, because a reader of a profile that departs from the baseline
            // twice should not have to reconstruct the baseline to see what it does.
            profile
                .Use<ParseStep>()
                .Use<ForbidNonceStep>()
                .Use<LogoutTokenTypeStep>()
                .Use<LogoutTokenExpiryStep>()
                .Use<EventsPresenceStep>()
                .Use<JwtIdPresenceStep>()
                .Use<IssuerAllowlistStep>()
                .Use<SignatureStep>()
                .Use<SubjectOrSessionStep>()
                .Use<LogoutEventStep>()
                .Use<AudienceStep>()
                .Use<IssuedAtWindowStep>()
                .Use<PayloadDeserializationStep>();

            // Declared beside the listing that adds them, so the two statements cannot drift.
            profile
                .AddCriticalStep<LogoutTokenTypeStep>()
                .AddCriticalStep<LogoutTokenExpiryStep>();

            profile
                .AllowInsecureValidation<TypHeaderStep>(
                    "A Logout Token may carry no 'typ' at all - Section 4.1 says requiring one 'will "
                    + "break most existing deployments' - so the replacement refuses a foreign type "
                    + "and accepts an absent one, which is a lower wall than the SET default's")
                .AllowInsecureValidation<ExpAbsenceStep>(
                    "Back-Channel Logout REQUIRES 'exp' (Section 2.6), inverting the SET default; the "
                    + "replacement polices the same claim with the opposite sign and also refuses one "
                    + "already past");
        });

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options);
        services.AddDistributedReplayCache();
        services.TryAddSingleton<ILogoutTokenValidator, LogoutTokenValidator>();
        services.TryAddSingleton<BackChannelLogoutHandler>();

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
    /// Registers key resolution that asks each issuer where its keys are, reading "jwks_uri" from
    /// that issuer's discovery document instead of pinning an address at composition time.
    /// </summary>
    /// <remarks>
    /// Why an address pinned at composition time is worth removing:
    /// <see cref="JwksKeyResolutionOptions.UseDiscoveryDocument"/>.
    /// <para>
    /// A named entry and any selector answer first, so a host that knows better about one issuer
    /// keeps saying so; discovery stands where the well-known guess otherwise stands.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Cache lifetimes and any issuer-specific overrides, as usual.</param>
    public static IServiceCollection AddDiscoveryKeyResolution(
        this IServiceCollection services,
        Action<JwksKeyResolutionOptions>? configure = null)
        => services.AddJwksKeyResolution(options =>
        {
            options.UseDiscoveryDocument = true;
            configure?.Invoke(options);
        });

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
