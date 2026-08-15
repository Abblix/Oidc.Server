// Abblix OIDC Server Library
// Copyright (c) Abblix LLP. All rights reserved.
//
// DISCLAIMER: This software is provided 'as-is', without any express or implied
// warranty. Use at your own risk. Abblix LLP is not liable for any damages
// arising from the use of this software.
//
// LICENSE RESTRICTIONS: This code may not be modified, copied, or redistributed
// in any form outside of the official GitHub repository at:
// https://github.com/Abblix/OIDC.Server. All development and modifications
// must occur within the official repository and are managed solely by Abblix LLP.
//
// Unauthorized use, modification, or distribution of this software is strictly
// prohibited and may be subject to legal action.
//
// For full licensing terms, please visit:
//
// https://oidc.abblix.com/license
//
// CONTACT: For license inquiries or permissions, contact Abblix LLP at
// info@abblix.com

using System.Net;
using System.Net.Mime;
using Abblix.SecurityEvents.BackChannelLogout;
using Abblix.SecurityEvents.MinimalApi;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.SecurityEvents.E2E.Tests;

/// <summary>
/// The back-channel logout route as a provider meets it: a real host, a real POST, and the answer
/// OpenID Connect Back-Channel Logout 1.0 Section 2.8 prescribes.
/// </summary>
/// <remarks>
/// The validator is substituted, not mocked, and the sink records - the question here is whether
/// the mapping carries a request to the handler and the handler's verdict back out, which no
/// amount of testing the handler alone can answer.
/// </remarks>
public sealed class BackChannelLogoutEndpointTests : IAsyncLifetime
{
    private const string Route = "/backchannel-logout";
    private const string Issuer = "https://op.example.com";

    private readonly RecordingSink _sink = new();
    private WebApplication _host = null!;

    /// <summary>
    /// Accepts one token and refuses every other, so a case chooses its outcome by what it posts.
    /// </summary>
    private sealed class StubValidator : ILogoutTokenValidator
    {
        public const string Accepted = "accepted.logout.token";

        public Task<LogoutNotification> ValidateAsync(
            string logoutToken, CancellationToken cancellationToken = default)
            => logoutToken == Accepted
                ? Task.FromResult(new LogoutNotification(Issuer, "user-1", "session-1", "jti-1"))
                : throw new LogoutTokenValidationException("The test's validator refuses this token.");
    }

    private sealed class RecordingSink : ILogoutNotificationSink
    {
        public List<LogoutNotification> Consumed { get; } = [];

        public Task<string?> ConsumeAsync(
            LogoutNotification notification, CancellationToken cancellationToken = default)
        {
            Consumed.Add(notification);
            return Task.FromResult<string?>(null);
        }
    }

    public async ValueTask InitializeAsync()
    {
        var builder = WebApplication.CreateSlimBuilder();
        builder.WebHost.UseTestServer();

        builder.Services.AddSingleton<ILogoutTokenValidator, StubValidator>();
        builder.Services.AddSingleton<ILogoutNotificationSink>(_sink);
        builder.Services.AddSingleton<BackChannelLogoutHandler>();

        _host = builder.Build();
        _host.MapBackChannelLogoutEndpoint(Route);

        await _host.StartAsync();
    }

    public async ValueTask DisposeAsync() => await _host.DisposeAsync();

    private Task<HttpResponseMessage> PostAsync(HttpContent content)
        => _host.GetTestClient().PostAsync(Route, content, TestContext.Current.CancellationToken);

    private static FormUrlEncodedContent Form(string logoutToken)
        => new([new KeyValuePair<string, string>("logout_token", logoutToken)]);

    [Fact]
    public async Task AValidLogoutRequest_Answers200_AndReachesTheSink()
    {
        using var response = await PostAsync(Form(StubValidator.Accepted));

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(Issuer, Assert.Single(_sink.Consumed).Issuer);

        // "The RP's response SHOULD include the Cache-Control HTTP response header field with a
        // no-store value" (Section 2.8).
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString());
    }

    [Fact]
    public async Task ARefusedToken_Answers400_WithTheErrorBody_AndNoStore()
    {
        using var response = await PostAsync(Form("something.else.entirely"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_sink.Consumed);

        // Section 2.8 sends the reader to RFC 6749 Section 5.2 for the body's members.
        var body = await response.Content.ReadAsStringAsync(TestContext.Current.CancellationToken);
        Assert.Contains(BackChannelLogoutError.ParameterNames.Error, body, StringComparison.Ordinal);
        Assert.Contains(BackChannelLogoutError.InvalidRequest, body, StringComparison.Ordinal);

        // The header is on the refusal too: a cached 400 would keep answering for a token that was
        // only invalid the first time.
        Assert.Contains("no-store", response.Headers.CacheControl!.ToString());
    }

    /// <summary>
    /// Section 2.5 fixes the encoding, and a request arriving as anything else never reaches
    /// validation.
    /// </summary>
    [Fact]
    public async Task AnotherContentType_Answers400()
    {
        using var response = await PostAsync(
            new StringContent(StubValidator.Accepted, null, MediaTypeNames.Application.Json));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
        Assert.Empty(_sink.Consumed);
    }
}
