// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Net;
using System.Net.Mime;
using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.SecurityEvents.BackChannelLogout;
using Abblix.SecurityEvents.Validation;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// A Logout Token whose session the application did not end can be delivered again, and the
/// second delivery reaches the application.
/// </summary>
/// <remarks>
/// The token is reserved while it is validated, which is before the application sees it. Section
/// 2.5 lets a provider retransmit when it suspects the first attempt failed, and a reservation that
/// outlived the failure answers that retransmission as a replay: the session then stays open until
/// the user ends it.
/// </remarks>
public class BackChannelLogoutRetryTests
{
    private const string Issuer = "https://op.example.com";
    private const string ClientId = "client_123";
    private const string Body = "logout_token=header.payload.signature";

    /// <summary>A profile that accepts whatever it is handed, so the case is about what follows it.</summary>
    private sealed class AcceptingProfile(SecurityEventToken token) : ISecurityEventTokenValidator
    {
        public ValueTask<SecurityEventTokenValidationError?> ValidateAsync(
            SecurityEventTokenValidationContext context,
            CancellationToken cancellationToken)
        {
            context.Token = token;
            return ValueTask.FromResult<SecurityEventTokenValidationError?>(null);
        }
    }

    public enum Failure
    {
        Refuses,
        Throws,
        IsCanceled,
    }

    /// <summary>Fails its first call in the way it was told to and ends the sessions on every later one.</summary>
    private sealed class SinkFailingOnce(Failure failure, CancellationTokenSource request) : ILogoutNotificationSink
    {
        public int Calls { get; private set; }

        public Task<string?> ConsumeAsync(
            LogoutNotification notification, CancellationToken cancellationToken = default)
        {
            if (Calls++ > 0)
                return Task.FromResult<string?>(null);

            switch (failure)
            {
                case Failure.Refuses:
                    return Task.FromResult<string?>("The session store did not answer.");

                case Failure.Throws:
                    throw new InvalidOperationException("The session store did not answer.");

                case Failure.IsCanceled:
                    request.Cancel();
                    throw new OperationCanceledException(request.Token);

                default:
                    throw new ArgumentOutOfRangeException(nameof(failure), failure, null);
            }
        }
    }

    private static SecurityEventToken LogoutToken()
    {
        var now = TimeProvider.System.GetUtcNow();

        var token = new JsonWebToken();
        token.Payload.Issuer = Issuer;
        token.Payload.Audiences = [ClientId];
        token.Payload.JwtId = "jti-1";
        token.Payload.Subject = "user_456";
        token.Payload.IssuedAt = now;
        token.Payload.ExpiresAt = now + TimeSpan.FromMinutes(2);
        return new SecurityEventToken(token);
    }

    /// <summary>
    /// The handler as the receiver's registration wires it, apart from the profile: the real
    /// validator reserving into the real cache, so the reservation the handler has to answer for
    /// is the one a deployment makes.
    /// </summary>
    private static BackChannelLogoutHandler Handler(ILogoutNotificationSink sink)
    {
        var options = new BackChannelLogoutValidationOptions
        {
            ExpectedAudience = ClientId,
            ExpectedIssuers = [Issuer],
        };

        var provider = new ServiceCollection()
            .AddSingleton<IDistributedCache>(
                new MemoryDistributedCache(Options.Create(new MemoryDistributedCacheOptions())))
            .AddSingleton<IReplayCache>(serviceProvider => new DistributedReplayCache(
                serviceProvider.GetRequiredService<IDistributedCache>(), TimeProvider.System, "replay:"))
            .AddSingleton<ILogoutTokenValidator>(serviceProvider => new LogoutTokenValidator(
                new AcceptingProfile(LogoutToken()), options, serviceProvider.GetRequiredService<IReplayCache>()))
            .AddSingleton<ILogger<BackChannelLogoutHandler>>(NullLogger<BackChannelLogoutHandler>.Instance)
            .AddSingleton(sink)
            .BuildServiceProvider();

        return ActivatorUtilities.CreateInstance<BackChannelLogoutHandler>(provider);
    }

    [Theory]
    [InlineData(Failure.Refuses)]
    [InlineData(Failure.Throws)]
    [InlineData(Failure.IsCanceled)]
    public async Task ATokenTheSinkFailedOn_ReachesTheSinkWhenDeliveredAgain(Failure failure)
    {
        using var firstRequest = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.Current.CancellationToken);
        var sink = new SinkFailingOnce(failure, firstRequest);
        var handler = Handler(sink);

        if (failure is Failure.Refuses)
        {
            var first = await handler.HandleAsync(
                MediaTypeNames.Application.FormUrlEncoded, Body, firstRequest.Token);
            Assert.Equal(HttpStatusCode.BadRequest, first.StatusCode);
        }
        else
        {
            var thrown = await Assert.ThrowsAnyAsync<Exception>(() => handler.HandleAsync(
                MediaTypeNames.Application.FormUrlEncoded, Body, firstRequest.Token));
            Assert.IsNotType<LogoutTokenValidationException>(thrown);
        }

        var second = await handler.HandleAsync(
            MediaTypeNames.Application.FormUrlEncoded, Body, TestContext.Current.CancellationToken);

        Assert.Equal(HttpStatusCode.OK, second.StatusCode);
        Assert.Equal(2, sink.Calls);
    }

    /// <summary>
    /// And a token the sink acted on stays reserved, so what a failure gives back is not given on
    /// success too - nor by a replay refused at validation, which never reserved anything to give.
    /// </summary>
    [Fact]
    public async Task ATokenTheSinkActedOn_IsRefusedWhenDeliveredAgain()
    {
        using var request = CancellationTokenSource.CreateLinkedTokenSource(
            TestContext.Current.CancellationToken);
        var sink = new SinkFailingOnce(Failure.Refuses, request);
        var handler = Handler(sink);

        await handler.HandleAsync(MediaTypeNames.Application.FormUrlEncoded, Body, request.Token);
        var acted = await handler.HandleAsync(MediaTypeNames.Application.FormUrlEncoded, Body, request.Token);
        var replayed = await handler.HandleAsync(MediaTypeNames.Application.FormUrlEncoded, Body, request.Token);
        var replayedAgain = await handler.HandleAsync(MediaTypeNames.Application.FormUrlEncoded, Body, request.Token);

        Assert.Equal(HttpStatusCode.OK, acted.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, replayed.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, replayedAgain.StatusCode);
        Assert.Equal(2, sink.Calls);
    }
}
