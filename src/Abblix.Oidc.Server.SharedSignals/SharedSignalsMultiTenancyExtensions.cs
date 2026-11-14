// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Common.Configuration;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SharedSignals.Telemetry;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Makes a Shared Signals transmitter per tenant.
/// </summary>
public static class SharedSignalsMultiTenancyExtensions
{
    /// <summary>
    /// Builds a transmitter for each tenant, bound to that tenant's issuer, part of the stores and signing keys,
    /// answers each request with the transmitter of the tenant serving it, runs push delivery for each tenant served,
    /// and deletes a released tenant's streams.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Wraps what the transmitter registration and the choice of stores registered, so those come before this call;
    /// startup refuses a server in which a later registration replaced a part this kept apart. Call it once.
    /// </para>
    /// <para>
    /// The stores, the outbox and the delivery lease the host chose hold every tenant's data, and each tenant's
    /// transmitter keeps its part of them apart by the tenant's space: a stream identifier alone does not, since a
    /// stream a tenant declares carries the identifier its operator chose, and two tenants may choose the same one.
    /// </para>
    /// </remarks>
    /// <param name="builder">What registering the server returned.</param>
    /// <returns>The same builder.</returns>
    public static IOidcServerBuilder AddSharedSignals(this IOidcServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var services = builder.Services;

        // A second call would wrap the stores again, and every stream would move to a different key.
        if (services.Any(descriptor => descriptor.ImplementationType == typeof(TenantSharedSignalsStartupCheck)))
        {
            throw new InvalidOperationException(
                $"{nameof(AddSharedSignals)}() has already been called on this server.");
        }

        if (services.All(descriptor => descriptor.ServiceType != typeof(IStreamStore)))
        {
            throw new InvalidOperationException(
                $"{nameof(AddSharedSignals)}() found no transmitter to make per tenant; register it with "
                + $"AddSharedSignalsTransmitter() before {nameof(AddSharedSignals)}().");
        }

        // The store and the outbox the host registered hold every tenant's data, so they are kept under keys of their
        // own, and each tenant's transmitter reaches its part of them
        SharedStores.Keep(services);
        DeclaredStreams(services);
        services.TryAddSingleton<TenantStreamStores>();
        services.TryAddSingleton<TransmitterAssembler>();
        services.TryAddSingleton<TenantTransmitterBuilder>();
        services.TryAddSingleton<TenantTransmitters>();

        // A request arriving while the tenants are still being loaded at startup reaches no tenant yet, so the
        // transmitter's endpoints wait for the load before they pick the transmitter of the tenant served
        TenantLoadReadiness.Register(services);

        // Each part a request, a host's job or an endpoint asks for is the part of the transmitter of the tenant served
        // when it asks, resolved anew each time; one held across requests refuses once used while another tenant is
        // served, rather than serving that tenant's events as its own.
        // Where no tenant is served, it is the part of a transmitter that refuses once it reaches a tenant's data:
        // an endpoint's parts are resolved before its filters run, and the filter answering 404 must get to run
        services.Replace(ServiceDescriptor.Transient(provider => Served(provider).Streams));
        services.Replace(ServiceDescriptor.Transient(provider => Served(provider).Outbox));
        services.Replace(ServiceDescriptor.Transient(provider => Served(provider).Identity));
        services.Replace(ServiceDescriptor.Transient(provider => Served(provider).Dispatcher));
        services.Replace(ServiceDescriptor.Transient(provider => Served(provider).Management));
        services.Replace(ServiceDescriptor.Transient(provider => Served(provider).PollHandler));
        services.Replace(ServiceDescriptor.Transient(provider => Served(provider).Signer));
        services.Replace(ServiceDescriptor.Transient(provider => Served(provider).Instruments));
        services.Replace(ServiceDescriptor.Transient(provider => Served(provider).PollEndpoints));
        services.Replace(ServiceDescriptor.Transient(provider => Served(provider).ManagementEndpoints));

        // The signer a host resolves reads the tenant served at each signing, so one kept across requests signs as
        // the right tenant; each tenant's transmitter signs through its own
        services.Replace(ServiceDescriptor.Singleton<ISecurityEventTokenSigner, TenantSecurityEventTokenSigner>());
        services.Replace(ServiceDescriptor.Singleton<IPushDeliverySweep, TenantPushDeliverySweep>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITenantClosing, TenantStreamsClosing>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IHostedService, TenantSharedSignalsStartupCheck>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, ServerWideStreamsValidator>());

        return builder;
    }

    /// <summary>
    /// The transmitter of the tenant the request or scope is served at, or the one serving no tenant.
    /// </summary>
    private static TenantTransmitter Served(IServiceProvider provider)
    {
        var transmitters = provider.GetRequiredService<TenantTransmitters>();
        return provider.GetRequiredService<ITenantAccessor>().Current is { } served
            ? transmitters.Serving(served.Tenant)
            : transmitters.None;
    }

    /// <summary>
    /// Declares the streams of the tenant <paramref name="tenantId"/> as configuration: they are that tenant's stream
    /// set, reconciled into its own part of the stream store the first time it is asked for its streams, so its
    /// receivers find them and no other tenant's does.
    /// </summary>
    /// <remarks>
    /// The declared streams are kept as a store of declared streams keeps them: the configuration owns what each stream
    /// is, the receiver what it has done through the management API since, and a stream of the tenant the
    /// configuration no longer declares is deleted. A tenant declares its streams in one call.
    /// <para>
    /// The server does not start when a tenant it serves at that moment declares a stream no request could be served
    /// from, or when its tenants are only those of its settings and none of them has the id.
    /// </para>
    /// </remarks>
    /// <param name="builder">What registering the server returned, after <see cref="AddSharedSignals"/>.</param>
    /// <param name="tenantId">The id of the tenant whose streams these are.</param>
    /// <param name="streams">The declared streams.</param>
    /// <returns>The same builder.</returns>
    public static IOidcServerBuilder AddConfiguredStreams(
        this IOidcServerBuilder builder,
        string tenantId,
        IReadOnlyList<ConfiguredStream> streams)
    {
        ArgumentNullException.ThrowIfNull(builder);
        ArgumentException.ThrowIfNullOrEmpty(tenantId);
        ArgumentNullException.ThrowIfNull(streams);

        if (builder.Services.All(descriptor => descriptor.ImplementationType != typeof(TenantSharedSignalsStartupCheck)))
        {
            throw new InvalidOperationException(
                $"{nameof(AddConfiguredStreams)}() declares streams of a transmitter made per tenant; call "
                + $"{nameof(AddSharedSignals)}() before it.");
        }

        DeclaredStreams(builder.Services).Declare(tenantId, streams);
        return builder;
    }

    /// <summary>
    /// The streams the tenants declare, registered on the first call.
    /// </summary>
    private static TenantConfiguredStreams DeclaredStreams(IServiceCollection services)
    {
        if (services.Select(descriptor => descriptor.ImplementationInstance)
                .OfType<TenantConfiguredStreams>()
                .SingleOrDefault() is { } declared)
        {
            return declared;
        }

        declared = new TenantConfiguredStreams();
        services.AddSingleton(declared);
        return declared;
    }
}
