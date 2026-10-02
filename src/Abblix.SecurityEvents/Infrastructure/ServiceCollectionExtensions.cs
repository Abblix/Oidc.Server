// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// Wires the security-event core into a host's service collection. Every registration lets a host
/// pre-registration win: the extension supplies defaults, never overrides. Profiles, key
/// resolution, replay and Back-Channel Logout each have their own class beside this one.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the security-event core: the event registry and the default verifier and
    /// signer over the Abblix JWT core. Validation is NOT wired here - each consumer creates
    /// its own named profile with
    /// <see cref="ValidationProfileServiceCollectionExtensions.AddSecurityEventValidationProfile"/>.
    /// </summary>
    /// <remarks>
    /// <para>
    /// This call registers NO validator: validation lives in named profiles, each created by
    /// <see cref="ValidationProfileServiceCollectionExtensions.AddSecurityEventValidationProfile"/>
    /// from the documented default steps and owned by the one consumer that names it. There is
    /// deliberately no unnamed shared family. It existed once, and it is the shape that produced the collision this API replaces: two
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
}
