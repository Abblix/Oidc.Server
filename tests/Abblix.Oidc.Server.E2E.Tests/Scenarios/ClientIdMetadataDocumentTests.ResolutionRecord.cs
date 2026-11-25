// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using Abblix.Oidc.Server.E2E.TestHost.TestInfrastructure;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Abblix.Oidc.Server.Features.Telemetry;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using OpenTelemetry.Trace;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class ClientIdMetadataDocumentTests
{
    /// <summary>
    /// The event id an operator alerts on for a client resolved from its document, as the server publishes it.
    /// </summary>
    private const int ClientResolvedEventId = 10628;

    /// <summary>
    /// A client resolved from its document is recorded once, by the lookup that first holds it, however many requests
    /// then read it; each endpoint span of its requests names it.
    /// </summary>
    [Fact]
    public async Task AClientResolvedFromItsDocument_IsRecordedOnce_AndNamedOnItsSpans()
    {
        var trace = ActivityTraceId.CreateRandom();
        var events = new OwnTraceEvents(trace);
        var spans = new OwnTraceSpans(trace);
        Serve(PublicClientDocument());
        await using var host = CreateHost(configureServices: services => services.AddOpenTelemetry()
            .WithTracing(tracing => tracing.AddSource(OidcTelemetry.SourceName).AddProcessor(spans))
            .WithLogging(logging => logging.AddProcessor(events)));
        var client = CreateClientFor(host);
        client.DefaultRequestHeaders.Add("traceparent", $"00-{trace}-{ActivitySpanId.CreateRandom()}-01");
        var discovery = await FetchDiscoveryAsync(client);

        for (var round = 0; round < 2; round++)
        {
            var (verifier, challenge) = GeneratePkcePair();
            var code = await AuthorizeAndExtractCodeAsync(client, discovery, CodeFlowParameters(ClientId, challenge));
            await ExchangeCodeForTokensAsync(client, discovery, CodeExchange(code, verifier));
        }

        var resolved = Assert.Single(events.Of(ClientResolvedEventId));
        Assert.Equal(LogLevel.Information, resolved.Level);
        Assert.Equal(TestTenantSettings.TenantId, resolved.Attributes["TenantId"]);
        Assert.Equal(ClientId, resolved.Attributes["ClientId"]);
        Assert.Equal(GrantTypes.AuthorizationCode, resolved.Attributes["GrantTypes"]);

        Assert.Equal(
            new[] { TelemetryEndpoints.Authorize, TelemetryEndpoints.Authorize, TelemetryEndpoints.Token, TelemetryEndpoints.Token },
            spans.Spans
                .Where(span => Equals(span.GetTagItem(TelemetryTags.ClientId), ClientId))
                .Select(span => (string)span.GetTagItem(TelemetryTags.Endpoint)!)
                .Order());
    }
}
