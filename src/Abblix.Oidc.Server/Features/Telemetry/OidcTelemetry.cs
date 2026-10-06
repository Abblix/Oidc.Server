// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using System.Reflection;

namespace Abblix.Oidc.Server.Features.Telemetry;

/// <summary>
/// The name the server's traces and metrics are published under, which a host passes to its OpenTelemetry setup to
/// receive them.
/// </summary>
/// <remarks>
/// The server records spans and measurements whether or not anything listens: a source nobody listens to starts no
/// span, an instrument nobody listens to records nothing, so the host's subscription is the only switch. With the
/// logging bridge on, a record the server logs while an endpoint span is open carries that span's trace and span.
/// The attributes are listed in <see cref="TelemetryTags"/>, the instruments in <see cref="OidcMetrics"/>.
/// <code>
/// services.AddOpenTelemetry()
///     .WithTracing(tracing => tracing.AddSource(OidcTelemetry.SourceName))
///     .WithMetrics(metrics => metrics.AddMeter(OidcTelemetry.SourceName))
///     .WithLogging();
/// </code>
/// </remarks>
public static class OidcTelemetry
{
    /// <summary>
    /// The name of the server's <see cref="ActivitySource"/> and of its meter.
    /// </summary>
    public const string SourceName = "Abblix.Oidc.Server";

    /// <summary>
    /// The version of the package, its build metadata left out, which the source and the meter carry.
    /// </summary>
    internal static readonly string? Version = typeof(OidcTelemetry).Assembly
        .GetCustomAttribute<AssemblyInformationalVersionAttribute>()?.InformationalVersion.Split('+')[0];

    /// <summary>
    /// The source the server starts its spans from.
    /// </summary>
    internal static readonly ActivitySource Source = new(SourceName, Version);
}
