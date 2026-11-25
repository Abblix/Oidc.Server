// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Diagnostics;
using Abblix.Oidc.Server.Common;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.E2E.Tests.TestInfrastructure;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using OpenTelemetry.Logs;
using Xunit;

namespace Abblix.Oidc.Server.E2E.Tests.Scenarios;

public partial class BackChannelAuthenticationTests
{
    /// <summary>
    /// The event id an operator alerts on for the tokens a token request is answered with, as the server publishes it.
    /// </summary>
    private const int TokensIssuedEventId = 11120;

    /// <summary>
    /// A push delivery mints its tokens without a request to the token endpoint, and they are recorded as any token
    /// request's are, under the CIBA grant, for the client and the subject the host completed the request for.
    /// </summary>
    [Fact]
    public async Task The_tokens_a_push_delivery_mints_are_recorded_under_the_ciba_grant()
    {
        var trace = ActivityTraceId.CreateRandom();
        var events = new OwnTraceEvents(trace);
        var deliveries = new NotificationRecorder();
        await using var host = CreateCibaHost(deliveries).WithWebHostBuilder(builder => builder.ConfigureTestServices(
            services => services.AddOpenTelemetry().WithLogging(logging => logging.AddProcessor(events))));
        var client = CreateClientFor(host);
        var discovery = await FetchDiscoveryAsync(client);
        var ciba = await RegisterPushCibaClientAsync(client, discovery);
        var authRequestId = await InitiateAsync(client, discovery, ciba, RequestedDetails, NotificationToken);

        // The host completes the request outside any request of its own; the trace tells this completion's records
        // apart from those of tests running alongside
        using (new Activity("completion").SetParentId(trace, ActivitySpanId.CreateRandom(), ActivityTraceFlags.Recorded).Start())
            await CompleteAsync(host, authRequestId, RequestedDetails);

        Assert.Single(deliveries.Received);
        var record = Assert.Single(events.Of(TokensIssuedEventId));
        Assert.Equal(LogLevel.Information, record.Level);
        Assert.Equal(GrantTypes.Ciba, record.Attributes["GrantType"]);
        Assert.Equal(ciba.ClientId, record.Attributes["ClientId"]);
        Assert.Equal(
            host.Services.GetRequiredService<CredentialFingerprints>().Of(LoginHint).ToString(),
            record.Attributes["Subject"]);
        Assert.DoesNotContain(record.Attributes.Values, value => value?.Contains(LoginHint) == true);
    }
}
