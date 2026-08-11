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

using System;
using System.Collections.Generic;
using System.Linq;
using System.Net.Http;
using Abblix.Oidc.Server.Features;
using Abblix.Oidc.Server.Features.BackChannelAuthentication;
using Abblix.Oidc.Server.Features.SecureHttpFetch;
using Abblix.Tests.Shared;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Http;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.SecureHttpFetch;

/// <summary>
/// A host that replaces the primary handler of a client registered with SSRF validation removes that validation,
/// and the build stays green. The library cannot forbid the swap without also forbidding a proxy or a client
/// certificate, so it reports it instead.
/// </summary>
public class SsrfGuardWatchTests
{
    [Fact]
    public void ReplacingThePrimaryHandler_IsReported()
    {
        var log = new CapturingLoggerProvider();
        using var provider = BuildHost(log, services => services
            .AddHttpClient(BackChannelNotificationTransport.HttpClientName)
            .ConfigurePrimaryHttpMessageHandler(() => new SocketsHttpHandler()));

        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(BackChannelNotificationTransport.HttpClientName);

        var entry = Assert.Single(log.Entries);
        Assert.Equal(LogLevel.Warning, entry.Level);
        Assert.Contains(BackChannelNotificationTransport.HttpClientName, entry.Message);
        Assert.Contains(nameof(SocketsHttpHandler), entry.Message);

        // The category is this type's own, which is what lets a host silence the message alone.
        Assert.Equal(typeof(SsrfGuardWatch).FullName, entry.Category);
    }

    /// <summary>
    /// The half that makes the report worth having: the ordinary way to add resilience does not trigger it, so the
    /// warning means what it says rather than crying wolf on every configured client.
    /// </summary>
    [Fact]
    public void AddingAResiliencePipeline_IsNotReported()
    {
        var log = new CapturingLoggerProvider();
        using var provider = BuildHost(log, services => services
            .AddHttpClient(BackChannelNotificationTransport.HttpClientName)
            .AddResilienceOfATypicalHost());

        using var handler = provider.GetRequiredService<IHttpMessageHandlerFactory>()
            .CreateHandler(BackChannelNotificationTransport.HttpClientName);

        Assert.Empty(log.Entries);
    }

    private static ServiceProvider BuildHost(
        CapturingLoggerProvider log,
        Action<IServiceCollection> configureHost)
    {
        var services = new ServiceCollection();
        services.AddLogging(builder => builder.AddProvider(log).SetMinimumLevel(LogLevel.Trace));
        services.AddOptions();
        services.AddSecureHttpFetch();
        services.AddBackChannelAuthentication();

        configureHost(services);
        return services.BuildServiceProvider();
    }

    private sealed record Entry(string Category, LogLevel Level, string Message);

    private sealed class CapturingLoggerProvider : ILoggerProvider
    {
        private readonly List<Entry> _entries = [];

        /// <summary>Only what this feature writes; the rest of the host's logging is noise here.</summary>
        public IReadOnlyList<Entry> Entries
            => _entries.Where(e => e.Category == typeof(SsrfGuardWatch).FullName).ToArray();

        public ILogger CreateLogger(string categoryName) => new Capturing(categoryName, _entries);

        public void Dispose()
        {
        }

        private sealed class Capturing(string category, List<Entry> entries) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => true;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
                => entries.Add(new Entry(category, logLevel, formatter(state, exception)));
        }
    }
}
