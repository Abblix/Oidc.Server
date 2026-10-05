// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Collections.Concurrent;
using System.Diagnostics;
using Abblix.Oidc.Server.Features.Telemetry;

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
}
