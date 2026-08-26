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
using Abblix.SharedSignals;
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
/// The CAEP Interoperability Profile 1.0 requires both members: Section 2.3.3 for jwks_uri and Section
/// 2.3.7 for authorization_schemes, whose value must include OAuth 2.0. The two are not equally optional
/// outside that profile. Shared Signals Framework 1.0 Section 7.1 attaches a condition to jwks_uri -
/// "This value MUST be specified if the Transmitter intends to generate signed JWTs" - and this package
/// always signs, so its absence is a violation there too. To authorization_schemes SSF attaches nothing.
/// A host is refused for neither, but a document that fails a conformance run should not do so in
/// silence.
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

        // The count is the message's only template argument, and nothing else here would notice it going
        // wrong: both other assertions match literals that live in the template itself.
        Assert.Contains(recorder.Warnings, message => message.Contains("The 1 configured"));
    }

    /// <summary>
    /// The control for both warnings. One that fires on every deployment is not a check, and one that
    /// fires on the DEFAULT would fire on every deployment that configures nothing.
    /// </summary>
    /// <remarks>
    /// Scoped to what this check looks at, and no count is given: the list grows, and a fixture that fires
    /// none of them is not thereby conformant overall - the check speaks about what a host configured, and
    /// the profile has requirements no configuration can be wrong about.
    /// </remarks>
    [Fact]
    public async Task AHostInsideTheProfile_IsNotWarned()
    {
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(
            BaseOptions() with
            {
                JwksUri = new Uri($"{Issuer}/jwks"),
                AuthorizationSchemes = [SchemeOf(SchemeUrns.OAuth2)],
                DefaultSubjectsMode = StreamSubjectsMode.All,
            },
            recorder,
            checksScopes: true);

        Assert.Empty(recorder.Warnings);
    }

    /// <summary>
    /// A transmitter whose new streams cover nothing is told so, because a receiver following the profile
    /// will never populate one and neither side will say why.
    /// </summary>
    /// <remarks>
    /// Section 2.4.4 tells the receiver to "assume that all subjects are implicitly included in a Stream,
    /// without any Add Subject method invocations". Section 2.3 puts no mirror on the transmitter, so this
    /// is not a clause a deployment violates - which is exactly why the default is left alone and the
    /// consequence is said out loud instead. The failure it prevents is the quietest kind: the dispatcher
    /// matches no stream, answers zero, and the receiver waits on a stream that reads as healthy.
    /// </remarks>
    [Fact]
    public async Task ATransmitterWhoseStreamsCoverNoSubject_IsWarnedAtStartup()
    {
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(BaseOptions(), recorder);

        Assert.Contains(recorder.Warnings, message => message.Contains("DefaultSubjectsMode"));
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

    /// <summary>
    /// An empty list is the host saying it advertises no scheme at all. The member is omitted rather than
    /// published empty, and nothing warns, because that is a decision rather than an oversight.
    /// </summary>
    [Fact]
    public async Task AHostThatAdvertisesNoScheme_PublishesNoMemberAndIsNotWarned()
    {
        var cancellationToken = TestContext.Current.CancellationToken;
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(
            BaseOptions() with
            {
                JwksUri = new Uri($"{Issuer}/jwks"),
                AuthorizationSchemes = [],
                DefaultSubjectsMode = StreamSubjectsMode.All,
            },
            recorder,
            checksScopes: true);

        var metadata = await ReadDocumentAsync(host, cancellationToken);

        Assert.Null(metadata.AuthorizationSchemes);
        Assert.Empty(recorder.Warnings);
    }

    /// <summary>
    /// The member is raw JSON because its shape is scheme-specific and belongs to the host, so reading it
    /// must answer the question rather than fault on a shape this package does not own.
    /// </summary>
    /// <remarks>
    /// A <c>spec_urn</c> that is not a string used to throw a JSON type error out of the route-mapping
    /// call, naming neither the member nor the option - an operator would have had nothing to go on.
    /// </remarks>
    [Fact]
    public async Task AHostWithANonStringSpecUrn_StartsAndIsWarned()
    {
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(
            BaseOptions() with
            {
                JwksUri = new Uri($"{Issuer}/jwks"),
                AuthorizationSchemes = [new JsonObject { ["spec_urn"] = 123 }],
            },
            recorder);

        Assert.Contains(recorder.Warnings, message => message.Contains(SchemeUrns.OAuth2));
    }

    /// <summary>
    /// The third thing this deployment can be outside the profile on, and the only one invisible from
    /// outside: the configuration document says the management API is OAuth-protected while the
    /// transmitter checks no scope at all.
    /// </summary>
    /// <remarks>
    /// Section 2.7.2 makes verifying a token's sufficiency a MUST. A host that never set
    /// <c>GrantedScopesSelector</c> has that switched off wholesale, and a receiver cannot tell -
    /// nothing it fetches differs. So the only place it can be said is the startup log.
    /// </remarks>
    [Fact]
    public async Task AHostThatChecksNoScope_IsWarnedAtStartup()
    {
        var recorder = new RecordingProvider();

        await using var host = await StartAsync(
            BaseOptions() with { JwksUri = new Uri($"{Issuer}/jwks") },
            recorder);

        Assert.Contains(recorder.Warnings, message => message.Contains("GrantedScopesSelector"));
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
        SharedSignalsTransmitterOptions options,
        ILoggerProvider? recorder = null,
        bool checksScopes = false)
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

        // Scope checking is the third thing the startup check looks at, so a fixture asserting NO warning
        // has to be inside the profile on that count too - otherwise it is asserting the absence of two
        // warnings while a third fires, which is a criterion that stops meaning what its name says.
        if (checksScopes)
        {
            builder.Services.AddSingleton(new SharedSignalsEndpointOptions
            {
                GrantedScopesSelector = _ => [SsfScopes.Manage],
            });
        }

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
    /// by hand rather than mocked, because the assertion is about the RENDERED text: the template and its
    /// arguments composed, which is what reaches a log and what neither half proves on its own.
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
