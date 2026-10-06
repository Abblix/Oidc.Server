// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.DocSamples.Samples;
using Microsoft.Extensions.DependencyInjection;
using OpenTelemetry.Metrics;
using OpenTelemetry.Trace;
using Xunit;

namespace Abblix.DocSamples;

/// <summary>
/// The documented host setup runs: a container built after it hands out the providers that receive the server's
/// traces and metrics.
/// </summary>
public sealed class OpenTelemetrySetupTests
{
    [Fact]
    public void TheDocumentedSetup_BuildsTheTracingAndMetricsProviders()
    {
        var services = new ServiceCollection();
        OpenTelemetrySetupSample.Configure(services);

        using var provider = services.BuildServiceProvider();

        Assert.NotNull(provider.GetService<TracerProvider>());
        Assert.NotNull(provider.GetService<MeterProvider>());
    }
}
