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
using Abblix.Oidc.Server.Endpoints.Authorization;
using Abblix.Oidc.Server.Endpoints.Authorization.Validation;
using Abblix.Oidc.Server.Endpoints.Authorization.Interfaces;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Features.ClientInformation;
using Abblix.Oidc.Server.Features.ClientAuthentication;
using Abblix.Oidc.Server.Features.RateLimiting;
using Abblix.Oidc.Server.Features.Consents;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Model;
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
    public async Task AClientAuthenticationFindingNoClient_ClosesItsSpanWithAnError()
    {
        var observed = new ObservedClientAuthenticator(Mock.Of<IClientAuthenticator>());

        var (_, stages) = await UnderAnEndpointSpan(() => observed.TryAuthenticateClientAsync(new ClientRequest()));

        var stage = Assert.Single(stages);
        Assert.Equal(TelemetryStages.ClientAuthentication, stage.GetTagItem(TelemetryTags.Stage));
        Assert.Equal(ActivityStatusCode.Error, stage.Status);
    }

    /// <summary>
    /// Reading the host's consents runs as a consent stage at the call, so a host replacing its provider keeps it.
    /// </summary>
    [Fact]
    public async Task ReadingTheConsents_RunsAsAConsentStage()
    {
        var inner = new Mock<IUserConsentsProvider>();
        inner
            .Setup(provider => provider.GetUserConsentsAsync(It.IsAny<ValidAuthorizationRequest>(), It.IsAny<AuthSession>()))
            .ReturnsAsync(new UserConsents());
        var reader = new UserConsentsReader(inner.Object, TimeProvider.System);
        var request = new ValidAuthorizationRequest(
            new AuthorizationValidationContext(new AuthorizationRequest()) { ClientInfo = new ClientInfo("client") });

        var (_, stages) = await UnderAnEndpointSpan(() => reader.ReadAsync(request, null!));

        Assert.Equal(TelemetryStages.Consent, Assert.Single(stages).GetTagItem(TelemetryTags.Stage));
    }

    [Fact]
    public async Task ASpentAuthenticationBudget_RefusesTheStageWithoutNamingAFailure()
    {
        // The throttling sits outside the client authentication's stage, so the refusal surfaces in the validation
        // stage around it, as a validator authenticating its client meets it
        var throttled = new Mock<IProbeStage>();
        throttled
            .Setup(stage => stage.CheckAsync("request"))
            .ThrowsAsync(new TooManyAuthenticationFailuresException(
                new TooManyRequestsError("Too many", null, CallerRateLimiters.AuthenticationFailures)));
        var observed = new ObservedProbeStage(throttled.Object);

        var (_, stages) = await UnderAnEndpointSpan(() => Assert.ThrowsAsync<TooManyAuthenticationFailuresException>(
            () => observed.CheckAsync("request")));

        var stage = Assert.Single(stages);
        Assert.Equal(ActivityStatusCode.Error, stage.Status);
        Assert.Null(stage.GetTagItem(TelemetryTags.ErrorType));
    }

    [Fact]
    public async Task AnActivityOfTheHostBetweenTheEndpointAndTheStage_LeavesTheStageTraced()
    {
        var (_, stages) = await UnderAnEndpointSpan(async () =>
        {
            using var host = new Activity("host").Start();
            await Stage("checked").CheckAsync("request");
        });

        Assert.Equal(TelemetryStages.Validation, Assert.Single(stages).GetTagItem(TelemetryTags.Stage));
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
