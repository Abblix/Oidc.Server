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
    /// Registers the receiver role: the push intake handler over the composed validation
    /// pipeline, with the three SSF profile steps joined into that pipeline in their required
    /// positions - the cheap "sub" rejection among the unverified checks, the stream-issuer
    /// binding among the trusted ones, the critical-members check last.
    /// </summary>
    /// <remarks>
    /// The host still owes two registrations of its own: an
    /// <see cref="Abblix.SharedSignals.Receiver.ISecurityEventSink"/>, because where events
    /// land is the application, and key resolution (for example
    /// <c>AddJwksKeyResolution</c>), because key trust is deployment knowledge. A replay cache
    /// (<c>AddDistributedReplayCache</c>) is optional and picked up when present.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="options">
    /// What this receiver expects of every token; registered as the shared instance, so a host
    /// pre-registering its own <see cref="SsfValidationOptions"/> wins.</param>
    public static IServiceCollection AddSsfReceiver(
        this IServiceCollection services,
        SsfValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        RequireSecurityEvents(services, nameof(AddSsfReceiver));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options);
        services.TryAddSingleton<PushDeliveryHandler>();

        // The SSF steps join the already-composed family through the live cursor; re-running
        // the registration must not double them, so each is added only on first sight. The
        // members live as KEYED descriptors, whose implementation type sits behind the keyed
        // property - the unkeyed one is null there, and a guard reading it would re-add on
        // every call.
        if (services.All(descriptor =>
                (descriptor.IsKeyedService
                    ? descriptor.KeyedImplementationType
                    : descriptor.ImplementationType) != typeof(ForbidSubStep)))
        {
            services.Decompose<ISecurityEventTokenValidator>()
                .AddAfter<ExpAbsenceStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, ForbidSubStep>())
                .AddAfter<AudienceStep>(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, StreamIssuerStep>())
                .AddLast(
                    ServiceDescriptor.Singleton<ISecurityEventTokenValidator, CriticalSubjectMembersStep>());

            // Two of the three carry the security-critical marker, and the marker only binds a profile that
            // knows about them: declared here, beside the registration that adds them, so the two statements
            // cannot drift apart.
            services.AddCriticalValidationStep<ForbidSubStep>();
            services.AddCriticalValidationStep<StreamIssuerStep>();
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
