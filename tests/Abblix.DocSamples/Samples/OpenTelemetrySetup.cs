// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Oidc.Server.Features.Telemetry;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;

namespace Abblix.DocSamples.Samples;

/// <summary>
/// The compiled copy of the sample documenting how a host receives the server's traces, metrics and correlated logs.
/// </summary>
/// <remarks>
/// The sample is a statement on the host's service collection, so the wrapper is a method taking it.
/// </remarks>
internal static class OpenTelemetrySetupSample
{
    internal static void Configure(IServiceCollection services)
    {
        // <sample>
        services.AddLogging(logging => logging.AddFilter(OidcTelemetry.LogCategory, LogLevel.Debug));
        services.AddOpenTelemetry()
            .WithTracing(tracing => tracing.AddAspNetCoreInstrumentation().AddSource(OidcTelemetry.SourceName))
            .WithMetrics(metrics => metrics.AddMeter(OidcTelemetry.SourceName))
            .WithLogging();
        // </sample>
    }
}
