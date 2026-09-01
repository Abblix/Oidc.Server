// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Abblix.Jwt.ReplayPrevention;
using Abblix.SharedSignals.Events;
using Abblix.SharedSignals.Receiver;
using Abblix.SharedSignals.Receiver.SecurityEvent;
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
    /// pre-registering its own <see cref="SharedSignalsTransmitterOptions"/> wins.</param>
    public static IServiceCollection AddSharedSignalsTransmitter(
        this IServiceCollection services,
        SharedSignalsTransmitterOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        RequireSecurityEvents(services, nameof(AddSharedSignalsTransmitter));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options);
        services.AddSharedSignalsEventTypes();
        services.TryAddSingleton<IStreamStore, InMemoryStreamStore>();
        services.TryAddSingleton<IEventOutbox, InMemoryEventOutbox>();

        // Every instance of the application runs the sweep below, so something must decide which
        // one delivers a given stream. The default reaches only inside this process, which is
        // right for one instance and named so a deployment reading its own startup log can see
        // that it is what got wired; the Redis delivery lease is the one that spans instances.
        services.TryAddSingleton<IDeliveryLease, ProcessLocalDeliveryLease>();

        // The issuer is a value, not a service, so the dispatcher is built through the factory
        // that overrides exactly that one parameter and resolves the rest - including the
        // sharing policy, which stays optional: a host that registered none runs without one.
        //
        // Resolved, not captured, for the reason the receiver half below states: TryAddSingleton lets
        // a host's own options instance win, so closing over the argument would sign every SET with a
        // value no other reader of the container sees. That one disagrees loudly at the far end and
        // silently here - the stream configuration and the discovery document both advertise the
        // container's issuer, so a receiver applying SSF 1.0 Section 7.2.2 refuses every token while
        // this side records the POST as delivered.
        services.TryAddSingleton(provider => provider.CreateService<EventDispatcher>(
            Dependency.Override<string>(
                serviceProvider => serviceProvider
                    .GetRequiredService<SharedSignalsTransmitterOptions>().Issuer)));

        // A singleton because the address is declared once, at startup, by whatever maps the poll
        // route, and read afterwards by everything that mints a stream.
        services.TryAddSingleton<PollEndpointLocator>();

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

        // Something has to drain the queues, and nothing else does: a host that wires the transmitter
        // and maps its endpoints watches events pile up with no error anywhere. A deployment driving
        // passes of its own opts out by setting PushDeliveryInterval to null, and this sweeper carries
        // no backoff, so leaving both running puts two pacing policies on one queue and the host's
        // configured ceiling means nothing while the flat one retries beside it.
        //
        // The opt-out is read INSIDE the scheduler rather than here, and that is the whole reason it is
        // registered unconditionally. TryAddSingleton above lets a host's own options instance win -
        // which the parameter documentation promises - so the argument and the container are two
        // sources for one fact. Deciding here would judge by the argument while every other reader saw
        // the host's, and the disagreement is silent in both directions: no sweeper where the host
        // configured one, or a sweeper the host opted out of.
        services.AddHostedService<PushDeliveryScheduler>();

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
    /// (<see cref="ValidationProfileKeys.SecurityEvent"/>) rather than by editing the host's plain
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
    /// <see cref="ISecurityEventSink"/>, because where events
    /// land is the application, and key resolution (for example
    /// <c>AddJwksKeyResolution</c>), because key trust is deployment knowledge. A replay cache
    /// (<c>AddDistributedReplayCache</c>) is optional and picked up when present.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="options">
    /// What this receiver expects of every token; registered as the shared instance, so a host
    /// pre-registering its own <see cref="SharedSignalsValidationOptions"/> wins.</param>
    public static IServiceCollection AddSharedSignalsReceiver(
        this IServiceCollection services,
        SharedSignalsValidationOptions options)
    {
        ArgumentNullException.ThrowIfNull(options);
        RequireSecurityEvents(services, nameof(AddSharedSignalsReceiver));

        services.TryAddSingleton(TimeProvider.System);
        services.TryAddSingleton(options);
        services.AddSharedSignalsEventTypes();

        // Every call this receiver makes outward goes through the factory, so one line of a host's
        // - ConfigureHttpClientDefaults, or a call naming one of the published transport names -
        // reaches all of them. A client the library merely ACCEPTS an HttpClient for is not on
        // that path: the host would have to build and wire it, and nothing would say so.
        services.AddHttpClient<PollClient>();
        services.AddHttpClient<TransmitterConfigurationClient>();

        // Named rather than typed, because the client it feeds is paired with the transmitter's
        // metadata, which a receiver learns at run time - so the factory builds it, not the
        // container.
        services.AddHttpClient(StreamManagementTransport.HttpClientName);
        services.TryAddSingleton<StreamManagementClientFactory>();

        // The push intake is RFC 8935's, not this framework's, so it takes the profile, the
        // expectations and the sink as parameters. Bound here because only this call knows which
        // profile is meant - and a keyed-service attribute could not say it, since an attribute
        // takes a compile-time constant while the key belongs to the registration.
        services.TryAddSingleton(provider => provider.CreateService<PushDeliveryHandler>(
            Dependency.Override<ISecurityEventTokenValidator>(
                serviceProvider => serviceProvider.GetRequiredKeyedService<ISecurityEventTokenValidator>(
                    ValidationProfileKeys.SecurityEvent)),
            // Resolved, not captured. TryAddSingleton above lets a host's own instance win, so
            // closing over the argument would judge tokens by the placeholder while every other
            // reader of the container saw the host's - one value with two sources, disagreeing
            // silently.
            Dependency.Override<SecurityEventTokenValidationOptions>(
                serviceProvider => serviceProvider.GetRequiredService<SharedSignalsValidationOptions>())));

        services.AddSecurityEventValidationProfileOnce(ValidationProfileKeys.SecurityEvent, profile =>
        {
            // The whole order a SET is judged in, written out: parse, then the rejections cheap
            // enough to make before any signature work, then the signature, then the checks that
            // read claims the issuer has now vouched for. The three SSF steps sit where that order
            // puts them - "sub" among the cheap ones, the stream issuer beside the audience it
            // qualifies, the critical members last, once payloads are typed.
            profile
                .Use<ParseStep>()
                .Use<TypHeaderStep>()
                .Use<ExpAbsenceStep>()
                .Use<ForbidSubStep>()
                .Use<EventsPresenceStep>()
                .Use<JwtIdPresenceStep>()
                .Use<IssuerAllowlistStep>()
                .Use<SignatureStep>()
                .Use<AudienceStep>()
                .Use<StreamIssuerStep>()
                .Use<IssuedAtWindowStep>()
                .Use<PayloadDeserializationStep>()
                .Use<CriticalSubjectMembersStep>();

            // Two of the three carry the security-critical marker, and the marker only binds a
            // profile that knows about them: declared here, beside the listing that adds them, so
            // the two statements cannot drift apart.
            profile
                .AddCriticalStep<ForbidSubStep>()
                .AddCriticalStep<StreamIssuerStep>();
        });

        return services;
    }

    /// <summary>
    /// Declares the transmitter's stream set as configuration: the store of a closed
    /// deployment whose receivers are the operator's own products - nothing to back up,
    /// lifecycle in the operator's file, API mutations ephemeral until restart.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Replace rather than TryAdd, deliberately: this call IS the host's explicit choice of
    /// store, so it wins whether it runs before or after
    /// <see cref="AddSharedSignalsTransmitter"/>'s in-memory default.
    /// </para>
    /// <para>
    /// The declarations are reconciled into a backing store, and this overload's is in memory -
    /// right for one instance, and the reason a receiver's pause reaches no further than the
    /// instance that took the request. A transmitter running several passes a shared one, which
    /// <c>AddSharedSignalsRedisConfiguredStreams</c> does.
    /// </para>
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="streams">The declared streams.</param>
    public static IServiceCollection AddSharedSignalsConfiguredStreams(
        this IServiceCollection services,
        IReadOnlyList<ConfiguredStream> streams)
        => services.AddSharedSignalsConfiguredStreams(streams, _ => new InMemoryStreamStore());

    /// <summary>
    /// Declares the transmitter's stream set as configuration, reconciled into a backing store the
    /// caller chooses - the form a deployment running more than one instance takes, so that the
    /// half of a stream its receiver owns is shared rather than per-instance.
    /// </summary>
    /// <remarks>
    /// The backing store is built by a factory rather than resolved from the container, because
    /// the container's <see cref="IStreamStore"/> is what this call registers: resolving it would
    /// hand the store itself.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    /// <param name="streams">The declared streams.</param>
    /// <param name="backingStore">Builds the store the declarations are reconciled into.</param>
    public static IServiceCollection AddSharedSignalsConfiguredStreams(
        this IServiceCollection services,
        IReadOnlyList<ConfiguredStream> streams,
        Func<IServiceProvider, IStreamStore> backingStore)
    {
        ArgumentNullException.ThrowIfNull(streams);
        ArgumentNullException.ThrowIfNull(backingStore);

        services.Replace(ServiceDescriptor.Singleton<IStreamStore>(provider =>
            provider.CreateService<ConfigurationStreamStore>(
                Dependency.Override(streams),
                Dependency.Override(backingStore(provider)))));

        return services;
    }

    /// <summary>
    /// Puts the transmitter's outbox on the host's <c>IDistributedCache</c>, so pending events
    /// survive a process restart when the store behind the cache does. Replace rather than
    /// TryAdd for the same reason as
    /// <see cref="AddSharedSignalsConfiguredStreams(IServiceCollection, IReadOnlyList{ConfiguredStream})"/>:
    /// an explicit choice wins in any order.
    /// </summary>
    /// <remarks>
    /// Surviving a restart and surviving a second instance are different properties, and this call
    /// buys the first only. <c>IDistributedCache</c> writes whole values with no compare-and-set,
    /// so two instances editing one stream's queue overwrite each other; a transmitter running
    /// more than one instance takes <c>AddSharedSignalsRedisOutbox</c> instead.
    /// </remarks>
    /// <param name="services">The service collection.</param>
    public static IServiceCollection AddSharedSignalsDistributedOutbox(this IServiceCollection services)
    {
        services.Replace(ServiceDescriptor.Singleton<IEventOutbox, DistributedCacheEventOutbox>());
        return services;
    }

    /// <summary>
    /// Teaches the event registry the two event types this framework defines for itself.
    /// </summary>
    /// <remarks>
    /// Through the options door, which is the registry's only one: a second registry instance
    /// would silently orphan whatever was registered through the first.
    /// </remarks>
    private static void AddSharedSignalsEventTypes(this IServiceCollection services)
        => services.Configure<SecurityEventsOptions>(options => options.Events.RegisterSharedSignalsEvents());

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
