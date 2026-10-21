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
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Makes a Shared Signals transmitter per tenant.
/// </summary>
public static class SharedSignalsMultiTenancyExtensions
{
    /// <summary>
    /// Keeps each tenant's streams apart, has the transmitter answer as the tenant serving the request and sign
    /// with that tenant's keys, runs push delivery for each tenant served, and deletes a released tenant's streams.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Wraps what the transmitter registration and the choice of stores registered, so those come before this call;
    /// startup refuses a server in which a later registration replaced a part this kept apart. Call it once.
    /// </para>
    /// <para>
    /// The queued events and the delivery claims need no wrapping: both are addressed by the stream, whose
    /// identifier the transmitter mints unique, and reached only through a stream found in the tenant's own store.
    /// </para>
    /// </remarks>
    /// <param name="builder">What registering the server returned.</param>
    /// <returns>The same builder.</returns>
    public static IOidcServerBuilder AddSharedSignals(this IOidcServerBuilder builder)
    {
        ArgumentNullException.ThrowIfNull(builder);
        var services = builder.Services;

        // A second call would wrap the stores again, and every stream would move to a different key.
        if (services.Any(descriptor => descriptor.ImplementationType == typeof(TenantSharedSignalsValidator)))
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

        services.Decorate<IStreamStore, TenantStreamStore>();
        DeclaredStreams(services);
        services.Decorate<IStreamStore, TenantConfiguredStreamStore>();
        services.Decorate<IPushDeliverySweep, TenantPushDeliverySweep>();
        services.Replace(ServiceDescriptor.Singleton<ITransmitterIdentity, TenantTransmitterIdentity>());
        services.Replace(ServiceDescriptor.Singleton<ISecurityEventTokenSigner, TenantSecurityEventTokenSigner>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITenantClosing, TenantStreamsClosing>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<OidcOptions>, TenantSharedSignalsValidator>());

        return builder;
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

        if (builder.Services.All(descriptor => descriptor.ImplementationType != typeof(TenantSharedSignalsValidator)))
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
