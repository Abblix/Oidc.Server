// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Abblix.Jwt;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.SharedSignals.E2E.Tests;

/// <summary>
/// Each startup warning reaches the host that has the surface it is about, and no other.
/// </summary>
/// <remarks>
/// The two surfaces are mapped by separate calls and a host may map either alone. A transmitter whose
/// streams come from configuration maps the document, because that is how a receiver finds it, and never
/// maps the management routes; a transmitter behind a gateway that answers the canonical address maps the
/// management routes with <c>MapWellKnownConfiguration</c> off. A warning attached to the wrong call is
/// wrong in both directions at once: noise for the first host, silence for the second, and the second is
/// the one exposing stream creation.
/// </remarks>
public sealed class CaepWarningsReachTheirOwnSurfaceTests
{
    private const string Issuer = "https://transmitter.example";

    /// <summary>
    /// The document alone: a host with no management routes hears nothing about scope checking or the
    /// default subjects mode, because it creates no streams and exposes no API to guard.
    /// </summary>
    [Fact]
    public async Task AHostMappingOnlyTheDocument_IsNotWarnedAboutTheManagementApi()
    {
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(recorder, app => app.MapSharedSignalsConfigurationDocument());

        Assert.DoesNotContain(recorder.Warnings, message => message.Contains("GrantedScopesSelector"));
        Assert.DoesNotContain(recorder.Warnings, message => message.Contains("DefaultSubjectsMode"));
    }

    /// <summary>
    /// The control for the row above: the same host DOES hear what the document itself is missing, so an
    /// empty warning list cannot pass for "the right warnings were suppressed".
    /// </summary>
    [Fact]
    public async Task AHostMappingOnlyTheDocument_IsStillWarnedAboutTheDocument()
    {
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(recorder, app => app.MapSharedSignalsConfigurationDocument());

        Assert.Contains(recorder.Warnings, message => message.Contains("jwks_uri"));
    }

    /// <summary>
    /// The management routes without the document: the host exposing stream creation with no scope check
    /// is told so, which is the case that used to start in silence.
    /// </summary>
    [Fact]
    public async Task AHostMappingTheManagementApiWithoutTheDocument_IsWarnedAboutScopeChecking()
    {
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(
            recorder,
            app => app.MapSharedSignalsTransmitterEndpoints(),
            new SharedSignalsEndpointOptions { MapWellKnownConfiguration = false });

        Assert.Contains(recorder.Warnings, message => message.Contains("GrantedScopesSelector"));
        Assert.Contains(recorder.Warnings, message => message.Contains("DefaultSubjectsMode"));
    }

    /// <summary>
    /// A host with both surfaces hears each warning once. This is the row a later edit would break by
    /// duplicating the management checks under the document while leaving them where they are, so the
    /// host that maps both hears them twice. Moving them back is a different edit, caught by the two
    /// single-surface rows above.
    /// </summary>
    [Fact]
    public async Task AHostMappingBothSurfaces_HearsEachWarningOnce()
    {
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(recorder, app => app.MapSharedSignalsTransmitterEndpoints());

        Assert.Equal(1, recorder.Warnings.Count(message => message.Contains("jwks_uri")));
        Assert.Equal(1, recorder.Warnings.Count(message => message.Contains("GrantedScopesSelector")));
        Assert.Equal(1, recorder.Warnings.Count(message => message.Contains("DefaultSubjectsMode")));
    }

    private static async Task<WebApplication> StartAsync(
        ILoggerProvider recorder,
        Action<WebApplication> map,
        SharedSignalsEndpointOptions? endpointOptions = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();
        builder.Logging.AddProvider(recorder);

        builder.Services.AddSecurityEvents(o =>
            o.SigningKeySource = _ => Task.FromResult<JsonWebKey>(
                JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)));

        // Deliberately outside the profile on every count the checks look at, so each row below asserts
        // which warning ARRIVES rather than which configuration is clean: no jwks_uri, no scope selector,
        // and new streams covering no subject.
        builder.Services.AddSharedSignalsTransmitter(new SharedSignalsTransmitterOptions
        {
            Issuer = Issuer,
            DefaultSubjectsMode = StreamSubjectsMode.None,
        });

        if (endpointOptions is not null)
        {
            builder.Services.AddSingleton(endpointOptions);
        }

        var app = builder.Build();
        map(app);
        await app.StartAsync();
        return app;
    }

    private sealed class RecordingProvider : ILoggerProvider
    {
        private readonly List<string> _warnings = [];

        public IReadOnlyList<string> Warnings
        {
            get
            {
                lock (_warnings) return _warnings.ToArray();
            }
        }

        public ILogger CreateLogger(string categoryName) => new Recorder(_warnings);

        public void Dispose()
        {
        }

        private sealed class Recorder(List<string> warnings) : ILogger
        {
            public IDisposable BeginScope<TState>(TState state) where TState : notnull => NullScope.Instance;

            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (!IsEnabled(logLevel))
                    return;

                lock (warnings) warnings.Add(formatter(state, exception));
            }
        }

        private sealed class NullScope : IDisposable
        {
            public static readonly NullScope Instance = new();

            public void Dispose()
            {
            }
        }
    }
}
