// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics;
using System.Diagnostics.Metrics;
using Abblix.Oidc.Server.Features.Telemetry;
using Microsoft.Extensions.DependencyInjection;

namespace Abblix.Oidc.Server.MultiTenancy.E2E.Tests;

public sealed partial class TenantIsolationTests
{
    /// <summary>
    /// An endpoint span names the tenant serving its request.
    /// </summary>
    [Fact]
    public async Task AnEndpointSpan_NamesTheTenantServingTheRequest()
    {
        var stopped = new ConcurrentBag<Activity>();
        using var listener = new ActivityListener
        {
            // Hosting too: its server span is what takes the trace the request carries
            ShouldListenTo = source => source.Name is OidcTelemetry.SourceName or "Microsoft.AspNetCore",
            Sample = (ref ActivityCreationOptions<ActivityContext> _) => ActivitySamplingResult.AllDataAndRecorded,
            ActivityStopped = activity => stopped.Add(activity),
        };
        ActivitySource.AddActivityListener(listener);

        async Task<string?> TenantNamedAt(string tenant)
        {
            // A trace of its own, so the spans of tests running alongside are told apart
            var trace = ActivityTraceId.CreateRandom();
            using var request = new HttpRequestMessage(HttpMethod.Get, tenant + ConfigurationPath);
            request.Headers.Add("traceparent", $"00-{trace}-{ActivitySpanId.CreateRandom()}-01");
            (await Http.SendAsync(request, TestContext.Current.CancellationToken)).EnsureSuccessStatusCode();

            var span = Assert.Single(stopped, span => span.Source.Name == OidcTelemetry.SourceName && span.TraceId == trace);
            return (string?)span.GetTagItem(TelemetryTags.Tenant);
        }

        Assert.Equal("acme", await TenantNamedAt(Acme));
        Assert.Equal("globex", await TenantNamedAt(Globex));
    }

    /// <summary>
    /// A request and the tokens it hands out are measured under the tenant serving it.
    /// </summary>
    [Fact]
    public async Task ARequestAndItsTokens_AreMeasuredUnderTheTenantServingIt()
    {
        var meters = _app!.Services.GetRequiredService<IMeterFactory>();
        var measured = new ConcurrentQueue<(string Instrument, string? Endpoint, string? Tenant)>();
        using var listener = new MeterListener
        {
            InstrumentPublished = (instrument, listener) =>
            {
                if (instrument.Meter.Name == OidcTelemetry.SourceName && ReferenceEquals(instrument.Meter.Scope, meters))
                    listener.EnableMeasurementEvents(instrument);
            },
        };
        void Record(Instrument instrument, ReadOnlySpan<KeyValuePair<string, object?>> tags)
        {
            var named = new Dictionary<string, object?>(tags.ToArray());
            measured.Enqueue((
                instrument.Name,
                (string?)named.GetValueOrDefault(TelemetryTags.Endpoint),
                (string?)named.GetValueOrDefault(TelemetryTags.Tenant)));
        }
        listener.SetMeasurementEventCallback<double>((instrument, _, tags, _) => Record(instrument, tags));
        listener.SetMeasurementEventCallback<long>((instrument, _, tags, _) => Record(instrument, tags));
        listener.Start();

        await AccessTokenOfADeviceFlowAsync(Acme);
        (await Http.GetAsync(Globex + ConfigurationPath, TestContext.Current.CancellationToken)).EnsureSuccessStatusCode();

        var tokenRequests = measured
            .Where(m => m is { Instrument: OidcMetrics.RequestDuration, Endpoint: TelemetryEndpoints.Token })
            .ToArray();
        Assert.NotEmpty(tokenRequests);
        Assert.All(tokenRequests, m => Assert.Equal("acme", m.Tenant));

        var issued = measured.Where(m => m.Instrument == OidcMetrics.TokensIssued).ToArray();
        Assert.NotEmpty(issued);
        Assert.All(issued, m => Assert.Equal("acme", m.Tenant));

        Assert.Contains(measured, m => m is
        {
            Instrument: OidcMetrics.RequestDuration,
            Endpoint: TelemetryEndpoints.Configuration,
            Tenant: "globex",
        });
    }
}
