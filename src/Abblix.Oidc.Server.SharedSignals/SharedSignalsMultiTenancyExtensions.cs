// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.DependencyInjection;
using Abblix.Oidc.Server.Features.MultiTenancy;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.Oidc.Server.SharedSignals;

/// <summary>
/// Makes a Shared Signals transmitter per tenant on a multi-tenant server.
/// </summary>
[Experimental(MultiTenancyDiagnostics.Experimental)]
public static class SharedSignalsMultiTenancyExtensions
{
    /// <summary>
    /// Keeps each tenant's streams apart, has the transmitter answer as the tenant serving the request and sign
    /// with that tenant's keys, runs push delivery for each tenant served, and deletes a released tenant's streams.
    /// </summary>
    /// <remarks>
    /// <para>
    /// Wraps what the transmitter registration and the choice of stores registered, so those come before
    /// <c>AddMultiTenancy</c>; startup refuses a server in which a later registration replaced a part this kept
    /// apart. Call it once.
    /// </para>
    /// <para>
    /// The queued events and the delivery claims need no wrapping: both are addressed by the stream, whose
    /// identifier the transmitter mints unique, and reached only through a stream found in the tenant's own store.
    /// </para>
    /// </remarks>
    /// <param name="builder">What turning multi-tenancy on returned.</param>
    /// <returns>The same builder.</returns>
    public static IMultiTenancyBuilder AddSharedSignals(this IMultiTenancyBuilder builder)
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
                + "AddSharedSignalsTransmitter() before AddMultiTenancy().");
        }

        services.Decorate<IStreamStore, TenantStreamStore>();
        services.Decorate<IPushDeliverySweep, TenantPushDeliverySweep>();
        services.Replace(ServiceDescriptor.Singleton<ITransmitterIdentity, TenantTransmitterIdentity>());
        services.Replace(ServiceDescriptor.Singleton<ISecurityEventTokenSigner, TenantSecurityEventTokenSigner>());
        services.TryAddEnumerable(ServiceDescriptor.Singleton<ITenantClosing, TenantStreamsClosing>());
        services.TryAddEnumerable(
            ServiceDescriptor.Singleton<IValidateOptions<MultiTenancyOptions>, TenantSharedSignalsValidator>());

        return builder;
    }
}
