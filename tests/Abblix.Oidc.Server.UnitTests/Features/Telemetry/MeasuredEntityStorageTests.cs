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
using System.Diagnostics.Metrics;
using System.Linq;
using System.Threading;
using System.Threading.Tasks;
using Abblix.Oidc.Server.Features.Storages;
using Abblix.Oidc.Server.Features.Telemetry;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.Telemetry;

/// <summary>
/// Each call to the server's entity storage is measured once under its operation, and runs as a stage of the request
/// while an endpoint's span is open.
/// </summary>
public sealed class MeasuredEntityStorageTests : IDisposable
{
    private readonly ServiceProvider _services = new ServiceCollection().AddMetrics().BuildServiceProvider();
    private readonly MeasurementRecorder _measured;
    private readonly MeasuredEntityStorage _storage;
    private readonly ConcurrentBag<Activity> _stopped = [];
    private readonly ActivityListener _listener;

    public MeasuredEntityStorageTests()
    {
        var meters = _services.GetRequiredService<IMeterFactory>();
        _measured = new MeasurementRecorder(meters);
        _storage = new MeasuredEntityStorage(
            Mock.Of<IEntityStorage>(),
            new OidcInstruments(NullLoggerFactory.Instance, meters));
        _listener = new ActivityListener
        {
            ShouldListenTo = source => source.Name == OidcTelemetry.SourceName,
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = _stopped.Add,
        };
        ActivitySource.AddActivityListener(_listener);
    }

    public void Dispose()
    {
        _listener.Dispose();
        _measured.Dispose();
        _services.Dispose();
    }

    [Fact]
    public async Task EachCall_IsMeasuredOnceUnderItsOperation()
    {
        var options = new StorageOptions();
        var token = TestContext.Current.CancellationToken;

        await _storage.SetAsync("key", "value", options, token);
        await _storage.GetAsync<string>("key", removeOnRetrieval: false, token);
        await _storage.TrySetIfAbsentAsync("key", "value", options, token);
        await _storage.RemoveAsync("key", token);

        Assert.Equal(
            [
                TelemetryStorageOperations.Set,
                TelemetryStorageOperations.Get,
                TelemetryStorageOperations.SetIfAbsent,
                TelemetryStorageOperations.Remove,
            ],
            _measured.Of(OidcMetrics.StorageOperationDuration).Select(tags => tags[TelemetryTags.StorageOperation]));
    }

    [Fact]
    public async Task ACallDuringAnEndpointsHandling_RunsAsAStorageStage()
    {
        Activity endpoint;
        using (endpoint = OidcTelemetry.Source.StartActivity("endpoint")!)
        {
            await _storage.RemoveAsync("key", TestContext.Current.CancellationToken);
        }

        var stage = Assert.Single(_stopped, span => span.ParentSpanId == endpoint.SpanId);
        Assert.Equal(TelemetryStages.Storage, stage.GetTagItem(TelemetryTags.Stage));
    }
}
