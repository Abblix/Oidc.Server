// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Buffers.Text;
using System.Net;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.MinimalApi;
using Abblix.SecurityEvents.Validation;
using Abblix.SecurityEvents.Validation.Steps;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Xunit;

namespace Abblix.SecurityEvents.E2E.Tests;

/// <summary>
/// A pushed SET is read as JWS compact serialization is everywhere else: RFC 7515 section 5.2 decodes each part
/// "following the restriction that no line breaks, whitespace, or other additional characters have been used", and
/// section 4 has the JOSE header's member names unique. A SET breaking either is a malformed transmission, which
/// RFC 8935 section 2.3 answers with 400 and "invalid_request".
/// </summary>
public sealed class PushDeliveryParsingTests : IAsyncLifetime
{
    private const string Route = "/push";

    private WebApplication _host = null!;

    public async ValueTask InitializeAsync()
    {
        var builder = WebApplication.CreateSlimBuilder(
            new WebApplicationOptions { EnvironmentName = Environments.Production });
        builder.WebHost.UseTestServer();
        builder.Services.AddSingleton(new PushDeliveryHandler(
            new ParseStep(), new SecurityEventTokenValidationOptions(), new NoSink()));
        _host = builder.Build();
        _host.MapPushDeliveryEndpoint(Route);
        await _host.StartAsync(TestContext.Current.CancellationToken);
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    public static TheoryData<string> MalformedTokens => new()
    {
        $"{Part("""{"alg":"RS256","alg":"none"}""")}.{Part("""{"iss":"https://transmitter.example.com"}""")}.sig",
        $"{Part("""{"alg":"RS256"}""")}.{Part("""{"iss":"a","iss":"b"}""")}.sig",
        $"{Part("""{"alg":"RS256"}""")}=.{Part("""{"iss":"https://transmitter.example.com"}""")}.sig",
        $"{Part("""{"alg":"RS256"}""")}.{Part("""{"iss":"https://transmitter.example.com"}""")} .sig",
    };

    [Theory]
    [MemberData(nameof(MalformedTokens))]
    public async Task AMalformedSet_IsAnsweredWithInvalidRequest(string token)
    {
        using var content = new StringContent(token);
        content.Headers.ContentType = MediaTypeHeaderValue.Parse(SecurityEventTokenMediaTypes.SecurityEventToken);

        using var response = await _host.GetTestClient().PostAsync(Route, content, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        using var body = JsonDocument.Parse(await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken));
        Assert.Equal(DeliveryErrorCodes.InvalidRequest, body.RootElement.GetProperty(DeliveryError.ParameterNames.Error).GetString());
    }

    private static string Part(string json) => Base64Url.EncodeToString(Encoding.UTF8.GetBytes(json));

    private sealed class NoSink : ISecurityEventSink
    {
        public Task<DeliveryError?> ConsumeAsync(
            ValidatedSecurityEventToken token,
            CancellationToken cancellationToken = default)
            => throw new InvalidOperationException("A malformed transmission never reaches the sink.");
    }
}
