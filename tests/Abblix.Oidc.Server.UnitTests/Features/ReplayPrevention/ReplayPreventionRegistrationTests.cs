// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Abblix.Jwt.ReplayPrevention;
using Abblix.Oidc.Server.Common.Configuration;
using Abblix.Oidc.Server.Common.Constants;
using Abblix.Oidc.Server.Features.ReplayPrevention;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.ReplayPrevention;

/// <summary>
/// Registering replay prevention more than once leaves one decorator, not one per call.
/// </summary>
/// <remarks>
/// Three unrelated feature registrations call <c>AddReplayPrevention</c>, so it has to survive being
/// called repeatedly. A second decorator is not a duplicate that cancels out: each layer widens the
/// retention window by the configured skew, so two layers retain for twice the skew and every
/// reservation is reported twice. Neither shows up as a failure anywhere - the cache still works, it
/// just remembers longer than the deployment asked.
/// <para>
/// Counted through the log rather than by looking at the object graph, because the log entry is what
/// the doubling actually produces: one layer reports a reservation once.
/// </para>
/// </remarks>
public class ReplayPreventionRegistrationTests
{
    private static readonly DateTimeOffset Now = new(2026, 1, 1, 0, 0, 0, TimeSpan.Zero);

    [Theory]
    [InlineData(1)]
    [InlineData(2)]
    [InlineData(3)]
    public async Task AddReplayPrevention_CalledSeveralTimes_LeavesOneDecorator(int calls)
    {
        var recorder = new RecordingLoggerProvider();

        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddProvider(recorder).SetMinimumLevel(LogLevel.Debug));
        services.AddDistributedMemoryCache();
        services.Configure<OidcOptions>(_ => { });
        services.AddSingleton<TimeProvider>(new FixedTimeProvider(Now));

        for (var i = 0; i < calls; i++)
            services.AddReplayPrevention();

        var cache = services.BuildServiceProvider().GetRequiredService<IReplayCache>();

        Assert.True(await cache.TryReserveAsync(
            "some-jti", Now.AddMinutes(5), TestContext.Current.CancellationToken));

        Assert.Equal(1, recorder.Count(LogEvents.Tokens.DistributedJwtReplayCache.MarkedAsUsed));
    }

    private sealed class FixedTimeProvider(DateTimeOffset now) : TimeProvider
    {
        public override DateTimeOffset GetUtcNow() => now;
    }

    private sealed class RecordingLoggerProvider : ILoggerProvider
    {
        private readonly List<int> _events = [];

        public int Count(int eventId)
        {
            lock (_events)
                return _events.FindAll(id => id == eventId).Count;
        }

        public ILogger CreateLogger(string categoryName) => new Recorder(_events);

        public void Dispose() { }

        private sealed class Recorder(List<int> events) : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                lock (events)
                    events.Add(eventId.Id);
            }
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose() { }
        }
    }
}
