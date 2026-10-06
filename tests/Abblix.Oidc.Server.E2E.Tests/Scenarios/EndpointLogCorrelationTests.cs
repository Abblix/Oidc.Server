// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.Features.Telemetry;
using Abblix.Oidc.Server.Model;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using OpenTelemetry.Trace;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

/// <summary>
/// With the OpenTelemetry logging bridge on, the record a refused request is logged with carries the trace and the
/// span of its endpoint span, and the error code the span names.
/// </summary>
public sealed class EndpointLogCorrelationTests(TestFactory factory) : TestBase(factory)
{
    private const string UnknownGrantType = "urn:example:grant-of-the-client";

    [Fact]
    public async Task A_refused_token_request_is_logged_under_its_token_span()
    {
        // One trace for every request of this test: the source is shared by every host in the process, so what
        // this test's requests produce is told apart by it
        var trace = ActivityTraceId.CreateRandom();
        var spans = new OwnTraceSpans(trace);
        var logs = new OwnTraceLogs(trace);

        await using var host = Factory.WithWebHostBuilder(builder => builder.ConfigureTestServices(services =>
        {
            services.AddLogging(logging => logging.AddFilter(typeof(OidcTelemetry).Namespace, LogLevel.Debug));
            services.AddOpenTelemetry()
                .WithTracing(tracing => tracing.AddSource(OidcTelemetry.SourceName).AddProcessor(spans))
                .WithLogging(logging => logging.AddProcessor(logs));
        }));
        var client = host.CreateClient(new WebApplicationFactoryClientOptions
        {
            AllowAutoRedirect = false,
            BaseAddress = TestServerAddress.BaseAddress,
        });

        client.DefaultRequestHeaders.Add("traceparent", $"00-{trace}-{ActivitySpanId.CreateRandom()}-01");

        var discovery = await FetchDiscoveryAsync(client);
        var refusal = await FormPostHelpers.PostFormAsync(client, discovery.TokenEndpoint, new Dictionary<string, string>
        {
            [ClientRequest.Parameters.ClientId] = TestConstants.ConfidentialClientId,
            [ClientRequest.Parameters.ClientSecret] = TestConstants.ConfidentialClientSecret,
            [TokenRequest.Parameters.GrantType] = UnknownGrantType,
        });
        Assert.False(refusal.IsSuccessStatusCode);

        var span = Assert.Single(spans.Spans, span => span.OperationName == TelemetryEndpoints.Token);
        var logged = Assert.Single(
            logs.Records,
            record => Equals(record.Attributes.GetValueOrDefault("Endpoint"), TelemetryEndpoints.Token));

        Assert.Equal(span.SpanId, logged.SpanId);
        Assert.Equal(ErrorCodes.UnauthorizedClient, span.GetTagItem(TelemetryTags.Error));
        Assert.Equal(span.GetTagItem(TelemetryTags.Error), logged.Attributes["Error"]);
    }
}
