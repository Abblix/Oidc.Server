// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Concurrent;
using System.Diagnostics;
using System.Linq;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Utils;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// A stage runs in a span of its own under the endpoint's span, closed with the status its outcome tells, and starts
/// none outside an endpoint's handling.
/// </summary>
public sealed class StageObservationTests : IDisposable
{
    private readonly ConcurrentBag<Activity> _stopped = [];
    private readonly ActivityListener _listener;

    public StageObservationTests()
    {
        _listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == OidcTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = _stopped.Add,
        };
        ActivitySource.AddActivityListener(_listener);
    }

    public void Dispose() => _listener.Dispose();

    private static ObservedProbeStage Stage(Result<string, int> outcome)
    {
        var inner = new Mock<IProbeStage>();
        inner.Setup(stage => stage.CheckAsync("request")).ReturnsAsync(outcome);
        return new ObservedProbeStage(inner.Object);
    }

    /// <summary>
    /// Runs <paramref name="act"/> under an endpoint span of the server, and returns that span and the stage spans of
    /// its trace.
    /// </summary>
    private async Task<(Activity Endpoint, Activity[] Stages)> UnderAnEndpointSpan(Func<Task> act)
    {
        Activity endpoint;
        using (endpoint = OidcTelemetry.Source.StartActivity("endpoint")!)
        {
            Assert.NotNull(endpoint);
            await act();
        }

        var stages = _stopped
            .Where(span => span.TraceId == endpoint.TraceId && span.SpanId != endpoint.SpanId)
            .ToArray();
        return (endpoint, stages);
    }

    [Fact]
    public async Task AStage_RunsInASpanUnderTheEndpointsSpan()
    {
        var (endpoint, stages) = await UnderAnEndpointSpan(() => Stage("checked").CheckAsync("request"));

        var stage = Assert.Single(stages);
        Assert.Equal(endpoint.SpanId, stage.ParentSpanId);
        Assert.Equal(TelemetryStages.Validation, stage.OperationName);
        Assert.Equal(TelemetryStages.Validation, stage.GetTagItem(TelemetryTags.Stage));
        Assert.Equal(ActivityStatusCode.Ok, stage.Status);
    }

    [Fact]
    public async Task ARefusingStage_ClosesItsSpanWithAnError()
    {
        var (_, stages) = await UnderAnEndpointSpan(() => Stage(42).CheckAsync("request"));

        Assert.Equal(ActivityStatusCode.Error, Assert.Single(stages).Status);
    }

    [Fact]
    public async Task AStageOutsideAnEndpoint_StartsNoSpan()
    {
        var before = Activity.Current;
        Activity.Current = null;
        try
        {
            Assert.True((await Stage("checked").CheckAsync("request")).TryGetSuccess(out _));
        }
        finally
        {
            Activity.Current = before;
        }

        Assert.DoesNotContain(_stopped, span => span.OperationName == TelemetryStages.Validation && span.Parent is null);
    }
}
