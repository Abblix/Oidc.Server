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
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Abblix.SharedSignals.Receiver;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.SharedSignals.Infrastructure;

/// <summary>
/// Wires the package into a host's service collection, one call per role. Both build on the
/// Security Events core the host has already wired - key trust and signing are deployment
/// knowledge that belongs to that call - and every registration here lets a host
/// pre-registration win: the extensions supply defaults, never overrides.
/// </summary>
public static class ServiceCollectionExtensions
{
    /// <summary>
    /// Registers the transmitter role: the in-memory stream store and outbox as replaceable
    /// defaults, the dispatcher, the management service, the poll endpoint handler, and the
    /// push sender as a typed HTTP client.
    /// </summary>
    /// <param name="services">The service collection.</param>
    /// <param name="options">
    /// The deployment's one-time decisions; registered as the shared instance, so a host
    /// pre-registering its own <see cref="SsfTransmitterOptions"/> wins.</param>
    public static IServiceCollection AddSsfTransmitter(
        this IServiceCollection services,
        SsfTransmitterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        RequireSecurityEvents(services, nameof(AddSsfTransmitter));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options);
        services.TryAddSingleton<IStreamStore, InMemoryStreamStore>();
        services.TryAddSingleton<IEventOutbox, InMemoryEventOutbox>();

        // The issuer is a value, not a service, so the dispatcher is built through the factory
        // that overrides exactly that one parameter and resolves the rest - including the
        // sharing policy, which stays optional: a host that registered none runs without one.
        services.TryAddSingleton(provider =>
            provider.CreateService<EventDispatcher>(Dependency.Override(options.Issuer)));

        services.TryAddSingleton<StreamManagementService>();
        services.TryAddSingleton<PollEndpointHandler>();

        // A receiver names the address its stream is delivered to, so that address is input from outside. The
        // policy judges it, and the validating handler puts that judgement on the connection itself - refusing
        // redirects and re-checking the address before every send - so a redirect or a DNS rebinding cannot carry
        // a delivery past the check.
        services.TryAddSingleton<ReceiverAddressPolicy>();
        services.TryAddTransient<ReceiverAddressValidatingHandler>();
        services
            .AddHttpClient<PushDeliverySender>()
            .ConfigurePrimaryHttpMessageHandler<ReceiverAddressValidatingHandler>();

        return services;
    }

    /// <summary>
    /// Registers the receiver role: the push intake handler over the receiver's OWN validation
    /// profile, with the three SSF steps joined in their required positions - the cheap "sub"
    /// rejection among the unverified checks, the stream-issuer binding among the trusted ones,
    /// the critical-members check last.
    /// </summary>
    /// <remarks>
    /// <para>
    /// The receiver validates under its own named profile
    /// (<see cref="SharedSignalsValidationProfiles.SecurityEvent"/>) rather than by editing the host's plain
    /// family. The plain family is shared, and another consumer of security event tokens in the
    /// same host - Back-Channel Logout is the live example - shapes it to demands a SET
    /// contradicts outright: its <c>typ</c> replacement refuses everything that is not a logout
    /// token, its <c>exp</c> replacement requires the claim a SET must not carry. Editing the
    /// shared family therefore either breaks that consumer or is broken by it, depending on
    /// registration order, and the loser sees every one of its tokens refused. A named profile
    /// removes the ordering from the outcome: each consumer owns its copy, and this package's
    /// steps and critical declarations bind to this profile alone.
    /// </para>
    /// <para>
    /// The host still owes two registrations of its own: an
    /// <see cref="Abblix.SharedSignals.Receiver.ISecurityEventSink"/>, because where events
    /// land is the application, and key resolution (for example
    /// <c>AddJwksKeyResolution</c>), because key trust is deployment knowledge. A replay cache
    /// (<c>AddDistributedReplayCache</c>) is optional and picked up when present.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="options">
    /// What this receiver expects of every token; registered as the shared instance, so a host
    /// pre-registering its own <see cref="SharedSignalsValidationOptions"/> wins.</param>
    public static IServiceCollection AddSsfReceiver(
        this IServiceCollection services,
        SharedSignalsValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        RequireSecurityEvents(services, nameof(AddSsfReceiver));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options);
        services.TryAddSingleton<PushDeliveryHandler>();

        // Re-running the registration must not double the profile, so it is created only on
        // first sight; the profile registration itself refuses a second creation loudly, which
        // is the right answer for anyone ELSE claiming this package's key.
        if (services.All(descriptor => !Equals(descriptor.ServiceKey, SharedSignalsValidationProfiles.SecurityEvent)))
        {
            services.AddSecurityEventValidationProfile(SharedSignalsValidationProfiles.SecurityEvent, profile =>
            {
                profile.Steps
                    .AddAfter<ExpAbsenceStep>(ServiceDescriptor.Singleton<ISecurityEventTokenValidator, ForbidSubStep>())
                    .AddAfter<AudienceStep>(ServiceDescriptor.Singleton<ISecurityEventTokenValidator, StreamIssuerStep>())
                    .AddLast(ServiceDescriptor.Singleton<ISecurityEventTokenValidator, CriticalSubjectMembersStep>());

                // Two of the three carry the security-critical marker, and the marker only binds a
                // profile that knows about them: declared here, beside the edit that adds them, so
                // the two statements cannot drift apart.
                profile
                    .AddCriticalStep<ForbidSubStep>()
                    .AddCriticalStep<StreamIssuerStep>();
            });
        }

        return services;
    }

    /// <summary>
    /// Declares the transmitter's stream set as configuration: the store of a closed
    /// deployment whose receivers are the operator's own products - nothing to back up,
    /// lifecycle in the operator's file, API mutations ephemeral until restart.
    /// </summary>
    /// <remarks>
    /// Replace rather than TryAdd, deliberately: this call IS the host's explicit choice of
    /// store, so it wins whether it runs before or after
    /// <see cref="AddSsfTransmitter"/>'s in-memory default.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="streams">The declared streams.</param>
    public static IServiceCollection AddSsfConfiguredStreams(
        this IServiceCollection services,
        IReadOnlyList<ConfiguredStream> streams)
    {
        ArgumentNullException.ThrowIfNull(streams);

        services.Replace(ServiceDescriptor.Singleton<IStreamStore>(provider =>
            provider.CreateService<ConfigurationStreamStore>(Dependency.Override(streams))));

        return services;
    }

    /// <summary>
    /// Puts the transmitter's outbox on the host's <c>IDistributedCache</c>, so pending events
    /// survive a process restart when the store behind the cache does. Replace rather than
    /// TryAdd for the same reason as <see cref="AddSsfConfiguredStreams"/>: an explicit choice
    /// wins in any order.
    /// </summary>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddSsfDistributedOutbox(this IServiceCollection services)
    {
        services.Replace(ServiceDescriptor.Singleton<IEventOutbox, DistributedCacheEventOutbox>());
        return services;
    }

    /// <summary>
    /// Both roles build on the Security Events core, and the marker of that call is the one
    /// registration it refuses to duplicate: the event type registry.
    /// </summary>
    private static void RequireSecurityEvents(IServiceCollection services, string caller)
    {
        if (services.All(descriptor => descriptor.ServiceType != typeof(EventTypeRegistry)))
        {
            throw new InvalidOperationException(
                $"{caller} builds on the Security Events core: call AddSecurityEvents(...) first - "
                + "key trust, signing and the validation pipeline are wired there.");
        }
    }
}
