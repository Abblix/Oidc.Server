// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using System.Diagnostics.Metrics;
using Abblix.DocSamples.Samples;
using Abblix.Oidc.Server.Features.Telemetry;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry.Logs;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Xunit;

namespace Abblix.DocSamples;

/// <summary>
/// The documented host setup runs, and what it builds listens to the server's source and meter by their published
/// name and bridges the host's logs.
/// </summary>
public sealed class OpenTelemetrySetupTests
{
    [Fact]
    public void TheDocumentedSetup_ListensToTheServersSourceAndMeterAndBridgesLogs()
    {
        var services = new ServiceCollection();
        OpenTelemetrySetupSample.Configure(services);

        // The exporter is the host's own choice; the metrics SDK listens to no meter until some reader collects
        services.ConfigureOpenTelemetryMeterProvider(metrics => metrics.AddInMemoryExporter(new List<Metric>()));

        using var provider = services.BuildServiceProvider();
        Assert.NotNull(provider.GetService<TracerProvider>());
        Assert.NotNull(provider.GetService<MeterProvider>());
        Assert.NotNull(provider.GetService<LoggerProvider>());

        // The providers subscribe by name, so a source and a meter of the server's name stand for the server's own,
        // which nothing else in this assembly listens to
        using var source = new ActivitySource(OidcTelemetry.SourceName);
        Assert.True(source.HasListeners());

        using var meter = new Meter(OidcTelemetry.SourceName);
        Assert.True(meter.CreateCounter<long>("probe").Enabled);
    }
}
