// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics.CodeAnalysis;
using Abblix.SharedSignals.Transmitter;
using Abblix.Utils;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Abblix.SharedSignals.Infrastructure;

/// <summary>
/// Refuses at startup a <see cref="SharedSignalsTransmitterOptions.OutboundProxy"/> that cannot name a forward proxy,
/// by <see cref="ForwardProxyAddress.WhyRefused"/>, rather than at the first delivery.
/// </summary>
/// <remarks>
/// The transmitter's decisions are an instance in the container rather than options, so the check rides the options
/// pipeline's startup validation through a marker of its own, and judges the instance the container holds - the one
/// the delivery guard is built from, a host's own registration included.
/// </remarks>
/// <param name="transmitter">The transmitter's decisions as the container holds them.</param>
internal sealed class OutboundProxyStartupCheck(SharedSignalsTransmitterOptions transmitter)
    : IValidateOptions<OutboundProxyStartupCheck.Marker>
{
    /// <summary>
    /// The options type the check is registered for; it carries nothing.
    /// </summary>
    [SuppressMessage("Major Code Smell", "S2094:Classes should not be empty",
        Justification = "The options pipeline validates per options type; this one exists only to be validated.")]
    internal sealed class Marker;

    /// <summary>
    /// Makes the host refuse to start with a proxy no transport can use, rather than the first delivery failing.
    /// </summary>
    public static void Register(IServiceCollection services)
    {
        services.TryAddEnumerable(ServiceDescriptor.Singleton<IValidateOptions<Marker>, OutboundProxyStartupCheck>());
        services.AddOptions<Marker>().ValidateOnStart();
    }

    /// <inheritdoc />
    public ValidateOptionsResult Validate(string? name, Marker options)
    {
        if (transmitter.OutboundProxy is { } proxy && ForwardProxyAddress.WhyRefused(proxy) is { } refusal)
        {
            return ValidateOptionsResult.Fail(
                $"{nameof(SharedSignalsTransmitterOptions)}.{nameof(SharedSignalsTransmitterOptions.OutboundProxy)}: " +
                $"{refusal}.");
        }

        return ValidateOptionsResult.Success;
    }
}
