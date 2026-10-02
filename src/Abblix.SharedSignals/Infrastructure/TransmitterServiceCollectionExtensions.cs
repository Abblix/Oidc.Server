// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DependencyInjection;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Abblix.SharedSignals.Infrastructure;

/// <summary>
/// Wires the transmitter role into a host's service collection, on top of the Security Events core
/// the host has already wired. Every registration here lets a host pre-registration win: the
/// extensions supply defaults, never overrides.
/// </summary>
public static class TransmitterServiceCollectionExtensions
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
        SharedSignalsRegistration.RequireSecurityEvents(services, nameof(AddSharedSignalsTransmitter));

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
        // Resolved, not captured, for the reason the receiver registration states: TryAddSingleton lets
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
        services.TryAddSingleton<ManagementEndpointLocator>();

        services.TryAddSingleton<StreamManagementService>();
        services.TryAddSingleton<PollEndpointHandler>();

        // A receiver names the address its stream is delivered to, so that address is input from outside. The
        // policy judges it, and the validating handler puts that judgment on the connection itself - refusing
        // redirects and re-checking the address before every send - so a redirect or a DNS rebinding cannot carry
        // a delivery past the check.
        // Built here rather than by the container's own constructor selection, which would fill the policy's
        // optional resolution parameter from any registration of that delegate - and a host that registered one
        // for something else would silently decide what every delivery address resolves to. A host that means to
        // replace the resolution registers this policy itself.
        services.TryAddSingleton(serviceProvider => new ReceiverAddressPolicy(
            serviceProvider.GetRequiredService<SharedSignalsTransmitterOptions>()));
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
}
