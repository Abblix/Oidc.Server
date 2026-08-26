// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SharedSignals.MinimalApi;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Abblix.SharedSignals.Transmitter;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace Abblix.SharedSignals.E2E.Tests;

/// <summary>
/// What a transmitter set up with nothing but an issuer actually publishes, measured through a real host
/// and the receiver's own client rather than off the options object.
/// </summary>
/// <remarks>
/// The CAEP Interoperability Profile 1.0 Section 2.3.7 requires the advertised authorization schemes to
/// include OAuth 2.0, and Section 2.4.3 requires a receiver to use OAuth 2.0 for Stream Management API
/// requests. Nothing in Shared Signals Framework 1.0 requires either member, so a host is never refused
/// here - but a conformance run measures against the profile, and a document that fails it should not do
/// so in silence.
/// </remarks>
public sealed class CaepProfileMetadataTests
{
    private const string Issuer = "https://transmitter.example";
    private const string SomeEvent = "https://tenant.example.com/events/membership-changed";
    private const string MutualTls = "urn:example:mutual-tls";

    [Fact]
    public async Task ATransmitterWithNothingButAnIssuer_AdvertisesOAuth()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(BaseOptions());

        var metadata = await ReadDocumentAsync(host, cancellationToken);

        Assert.NotNull(metadata.AuthorizationSchemes);
        Assert.Contains(metadata.AuthorizationSchemes, IsOAuth);
    }

    /// <summary>
    /// The control, and the boundary of the default: a host supplying its own list gets exactly that
    /// list. Without this a builder that appended the OAuth entry to everything would pass the test
    /// above.
    /// </summary>
    [Fact]
    public async Task AHostThatSuppliesItsOwnSchemes_GetsExactlyThose()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        await using var host = await StartAsync(BaseOptions() with
        {
            AuthorizationSchemes = [SchemeOf(MutualTls)],
        });

        var metadata = await ReadDocumentAsync(host, cancellationToken);

        var scheme = Assert.Single(metadata.AuthorizationSchemes!);
        Assert.Equal(MutualTls, SpecUrnOf(scheme));
    }

    /// <summary>
    /// A host that takes the member over and leaves OAuth 2.0 out is told once, at startup. The silence
    /// is the whole defect: the document is served, every request succeeds, and the conformance run is
    /// where the deployment would otherwise find out.
    /// </summary>
    [Fact]
    public async Task AHostThatDropsOAuth_IsWarnedAtStartup()
    {
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(
            BaseOptions() with
            {
                JwksUri = new Uri($"{Issuer}/jwks"),
                AuthorizationSchemes = [SchemeOf(MutualTls)],
            },
            recorder);

        Assert.Contains(recorder.Warnings, message => message.Contains(SchemeUrns.OAuth2));
    }

    /// <summary>
    /// The control for the warning. One that fires on every deployment is not a check, and one that
    /// fires on the DEFAULT would fire on every deployment that configures nothing.
    /// </summary>
    [Fact]
    public async Task AHostInsideTheProfile_IsNotWarnedAtAll()
    {
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(
            BaseOptions() with
            {
                JwksUri = new Uri($"{Issuer}/jwks"),
                AuthorizationSchemes = [SchemeOf(SchemeUrns.OAuth2)],
            },
            recorder);

        Assert.Empty(recorder.Warnings);
    }

    /// <summary>
    /// The other member the profile requires and this package cannot default, because only the host knows
    /// where its JWK Set is published. Section 2.4.2 sends a receiver to it for the signing keys, so
    /// without it a receiver under that profile can verify nothing at all.
    /// </summary>
    [Fact]
    public async Task ATransmitterWithNoJwksUri_IsWarnedAtStartup()
    {
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(BaseOptions(), recorder);

        Assert.Contains(recorder.Warnings, message => message.Contains("jwks_uri"));
    }

    private static SharedSignalsTransmitterOptions BaseOptions() => new()
    {
        Issuer = Issuer,
        EventsSupported = [SomeEvent],
    };

    private static JsonObject SchemeOf(string specUrn)
        => new() { [TransmitterConfiguration.ParameterNames.SpecUrn] = specUrn };

    private static string? SpecUrnOf(JsonObject scheme)
        => scheme[TransmitterConfiguration.ParameterNames.SpecUrn]?.GetValue<string>();

    private static bool IsOAuth(JsonObject scheme) => SpecUrnOf(scheme) == SchemeUrns.OAuth2;

    private static async Task<WebApplication> StartAsync(
        SharedSignalsTransmitterOptions options, ILoggerProvider? recorder = null)
    {
        var builder = WebApplication.CreateBuilder();
        builder.WebHost.UseTestServer();
        builder.Logging.ClearProviders();

        if (recorder is not null)
        {
            builder.Logging.AddProvider(recorder);
        }

        builder.Services.AddSecurityEvents(o =>
            o.SigningKeySource = _ => Task.FromResult<JsonWebKey>(
                JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256)));
        builder.Services.AddSharedSignalsTransmitter(options);

        var app = builder.Build();
        // Maps the well-known configuration document too, which is where the profile check runs.
        app.MapSharedSignalsTransmitterEndpoints();
        await app.StartAsync();
        return app;
    }

    private static Task<TransmitterConfiguration> ReadDocumentAsync(
        WebApplication host, CancellationToken cancellationToken)
        => new TransmitterConfigurationClient(host.GetTestClient())
            .GetAsync(new Uri(Issuer), cancellationToken);

    private static class SchemeUrns
    {
        public const string OAuth2 = TransmitterConfiguration.AuthorizationSchemeUrns.OAuth2;
    }

    /// <summary>
    /// Records warning-level messages so a test can assert on what an operator would have seen. Written
    /// by hand rather than mocked, because the assertion is about the RENDERED text - which is what
    /// reaches a log, and what a template argument mistake would break.
    /// </summary>
    private sealed class RecordingProvider : ILoggerProvider
    {
        public List<string> Warnings { get; } = [];

        public ILogger CreateLogger(string categoryName) => new Recorder(Warnings);

        public void Dispose()
        {
        }

        private sealed class Recorder(List<string> warnings) : ILogger
        {
            public IDisposable? BeginScope<TState>(TState state) where TState : notnull => null;

            public bool IsEnabled(LogLevel logLevel) => logLevel >= LogLevel.Warning;

            public void Log<TState>(
                LogLevel logLevel,
                EventId eventId,
                TState state,
                Exception? exception,
                Func<TState, Exception?, string> formatter)
            {
                if (logLevel >= LogLevel.Warning)
                {
                    warnings.Add(formatter(state, exception));
                }
            }
        }
    }
}
