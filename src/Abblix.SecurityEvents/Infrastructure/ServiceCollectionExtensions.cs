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
        services.Compose<ISecurityEventTokenValidator, CompositeSecurityEventTokenValidator>();
        services.Decorate<ISecurityEventTokenValidator, InsecureValidationGuard>();

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
