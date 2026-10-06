// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using System.Diagnostics.Metrics;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Model;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// A span nobody records costs the host's enrichers nothing.
/// </summary>
/// <remarks>
/// Whether a span is recorded is decided by every listener of the server's source in the process together, so the
/// class runs alone: another test's listener recording everything would record this span too.
/// </remarks>
[Collection(nameof(UnrecordedSpanTests))]
[CollectionDefinition(nameof(UnrecordedSpanTests), DisableParallelization = true)]
public sealed class UnrecordedSpanTests
{
    [Fact]
    public async Task AnEnricherOfTheHost_IsNotAskedForASpanNobodyRecords()
    {
        // A listener that keeps only the trace's context, so the span exists and is not recorded
        using var listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == OidcTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.PropagationData,
        };
        ActivitySource.AddActivityListener(listener);
        await using var services = new ServiceCollection().AddMetrics().BuildServiceProvider();
        var instruments = new OidcInstruments(NullLoggerFactory.Instance, services.GetRequiredService<IMeterFactory>());
        var enricher = new Mock<IEndpointSpanEnricher>();

        await EndpointObservation.RunAsync(
            TelemetryEndpoints.Token,
            instruments,
            null,
            () => Task.FromResult(0),
            EndpointObservation.NoError,
            enrichment: new EndpointEnrichment(new TokenRequest(), [enricher.Object]));

        enricher.Verify(e => e.Enrich(It.IsAny<Activity>(), It.IsAny<string>(), It.IsAny<object?>()), Times.Never);
    }
}
