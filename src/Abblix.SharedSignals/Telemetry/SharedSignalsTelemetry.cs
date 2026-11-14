// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using System.Reflection;

namespace Abblix.SharedSignals.Telemetry;

/// <summary>
/// The name the transmitter's traces and metrics are published under, which a host passes to its OpenTelemetry setup
/// to receive them.
/// </summary>
/// <remarks>
/// The transmitter records spans and measurements whether or not anything listens: a source nobody listens to starts
/// no span, an instrument nobody listens to records nothing, so the host's subscription is the only switch. Push
/// delivery runs on a timer outside any request, so its spans are roots of their own traces, and a stream whose
/// receiver address the delivery policy refuses records none, since nothing is posted to it. An event dispatched
/// while a request is handled is traced under that request's span; a host without instrumentation of its own
/// requests starts that span unrecorded, and the default sampler then drops the transmitter's spans under it, so the
/// setup instruments them too. No span or measurement names a stream, a receiver's address or a subject. The
/// attributes are listed in <see cref="SharedSignalsTags"/>, the instruments in <see cref="SharedSignalsMetrics"/>.
/// <code>
/// services.AddOpenTelemetry()
///     .WithTracing(tracing => tracing.AddAspNetCoreInstrumentation().AddSource(SharedSignalsTelemetry.SourceName))
///     .WithMetrics(metrics => metrics.AddMeter(SharedSignalsTelemetry.SourceName));
/// </code>
/// </remarks>
public static class SharedSignalsTelemetry
{
    /// <summary>
    /// The name of the transmitter's <see cref="ActivitySource"/> and of its meter.
    /// </summary>
    public const string SourceName = "Abblix.SharedSignals";

    /// <summary>
    /// The span of one security event minted for one stream and put into its outbox.
    /// </summary>
    public const string TransmitSpan = "ssf.transmit";

    /// <summary>
    /// The span of one security event token posted to a receiver's push endpoint, until its answer is acted on.
    /// </summary>
    public const string PushSpan = "ssf.push";

    /// <summary>
    /// The version of the package, its build metadata left out, which the source and the meter carry.
    /// </summary>
    internal static readonly string? Version = typeof(SharedSignalsTelemetry).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0];

    /// <summary>
    /// The source the transmitter starts its spans from.
    /// </summary>
    internal static readonly ActivitySource Source = new(SourceName, Version);
}
