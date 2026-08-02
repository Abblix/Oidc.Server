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

using Abblix.Jwt;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Abblix.SecurityEvents.Infrastructure;

/// <summary>
/// Wires the package into a host's service collection. Every registration lets a host
/// pre-registration win: the extension supplies defaults, never overrides.
/// </summary>
public static partial class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the security-event core: the validator over the configured profile, the event
    /// registry, and the default verifier and signer over the Abblix JWT core.
    /// </summary>
    /// <remarks>
    /// Two of the defaults ask for more configuration before they resolve, and each fails loudly
    /// naming what is missing: the verifier needs an <see cref="IIssuerKeyResolver"/> - key trust
    /// is deployment knowledge - and the signer needs
    /// <see cref="SecurityEventsOptions.SigningKeySource"/>, which only a transmitter has. A pure
    /// receiver registers a resolver and never touches signing; a pure transmitter does the
    /// reverse.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="configure">Configures the profile, the event dictionary, and signing.</param>
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

        services.TryAddSingleton<EventTypeRegistry>(
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

        services.TryAddSingleton<SecurityEventTokenValidator>(provider =>
        {
            var pipeline = provider.GetRequiredService<IOptions<SecurityEventsOptions>>().Value.Validation;
            if (pipeline.StepTypes.Count == 0)
            {
                pipeline.UseDefaultPipeline();
            }

            // A weakened pipeline must be visible in the boot log, not only at the composition
            // site - this is where the AllowInsecure reasons surface operationally.
            if (provider.GetService<ILoggerFactory>() is { } loggerFactory)
            {
                var logger = loggerFactory.CreateLogger<SecurityEventTokenValidator>();
                foreach (var allowance in pipeline.InsecureAllowances)
                {
                    LogInsecurePipelineAllowance(logger, allowance);
                }
            }

            return new SecurityEventTokenValidator(pipeline.Build(type => ResolveStep(provider, type)));
        });

        return services;
    }

    /// <summary>
    /// Registers the process-local replay cache as the <see cref="IJtiReplayCache"/>.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="retention">
    /// How long identifiers are remembered past their tokens' issue time; must cover the
    /// validation profile's issued-at tolerance with a margin. The default doubles the default
    /// tolerance of <see cref="SecurityEventTokenValidationOptions.IssuedAtTolerance"/>.</param>
    public static IServiceCollection AddInMemoryReplayCache(
        this IServiceCollection services,
        TimeSpan? retention = null)
    {
        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton<IJtiReplayCache>(
            provider => new InMemoryJtiReplayCache(
                provider.GetRequiredService<TimeProvider>(),
                retention ?? TimeSpan.FromMinutes(10)));

        return services;
    }

    /// <summary>
    /// Creates a pipeline step: a host-registered instance when there is one, so a host can
    /// configure a step as a service, and a container-constructed instance otherwise, so the
    /// default steps and a consumer's custom steps need no registration of their own.
    /// </summary>
    private static ISecurityEventTokenValidationStep ResolveStep(IServiceProvider provider, Type stepType)
        => provider.GetService(stepType) as ISecurityEventTokenValidationStep
            ?? (ISecurityEventTokenValidationStep)ActivatorUtilities.CreateInstance(provider, stepType);

    [LoggerMessage(
        EventId = LogEvents.Composition.InsecurePipelineAllowance,
        Level = LogLevel.Warning,
        Message = "The validation pipeline was weakened under an explicit allowance: {Allowance}")]
    private static partial void LogInsecurePipelineAllowance(ILogger logger, string allowance);
}
