// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

using System.Runtime.CompilerServices;
using System.Text;
using System.Text.Json;
using Abblix.Jwt;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Delivery;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Validation;
using Abblix.SharedSignals.Infrastructure;
using Abblix.SharedSignals.Receiver;
using Abblix.SharedSignals.Receiver.SecurityEvent;
using Abblix.SharedSignals.Transmitter;
using Abblix.SharedSignals.Events;
using Abblix.SharedSignals.Model;
using Abblix.SharedSignals.Model.Delivery;
using Abblix.SecurityEvents.Subjects;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the wiring: each role resolves whole from one call over the Security Events core, a
/// host pre-registration wins over the package default, the missing prerequisite fails loudly
/// naming it, and the SSF profile steps actually RUN inside the composed pipeline - proven by
/// a verdict only they produce, not by their registrations existing.
/// </summary>
public class SharedSignalsServiceCollectionTests
{
    private static SharedSignalsTransmitterOptions TransmitterOptions => new()
    {
        Issuer = "https://tr.example.com",
        PollEndpointFactory = streamId => new Uri($"https://tr.example.com/ssf/poll/{streamId}"),
    };

    /// <summary>
    /// The Security Events core plus the two deployment-knowledge seams a real host wires with
    /// keys - faked here, because these tests measure wiring, not cryptography.
    /// </summary>
    /// <summary>A signer that keeps what it was handed, so a test can read what was minted.</summary>
    private sealed class RecordingSigner : ISecurityEventTokenSigner
    {
        public List<SecurityEventToken> Signed { get; } = [];

        public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
        {
            Signed.Add(token);
            return Task.FromResult($"signed.{token.JwtId}");
        }
    }

    /// <summary>Every SET is signed with the issuer the CONTAINER holds, not the one this call was handed.</summary>
    /// <remarks>
    /// <para>
    /// The registration takes options as an argument and hands them over with TryAddSingleton, so a host
    /// that registered its own instance first keeps it - which is the whole of what the parameter
    /// documentation promises. Capturing the argument into the dispatcher would therefore sign every
    /// token with a value no other reader of the container sees.
    /// </para>
    /// <para>
    /// That disagreement is the loudest one this package can produce and the hardest to trace. The
    /// stream configuration and the discovery document both carry the container's issuer, so a
    /// conforming receiver checks "iss" against them (SSF 1.0 Section 7.2.2, and this library's own
    /// StreamIssuerStep) and refuses every token - while this side records each POST as delivered.
    /// Two logs, no shared identifier, and both of them describing a healthy system.
    /// </para>
    /// </remarks>
    [Fact]
    public async Task TheIssuerIsResolved_NotCaptured()
    {
        const string hostIssuer = "https://tr.host.example.com";
        var cancellationToken = TestContext.Current.CancellationToken;

        var signer = new RecordingSigner();
        var services = SecurityEventsBase();
        services.AddSingleton<ISecurityEventTokenSigner>(signer);

        // Registered BEFORE the package call, which is what makes its TryAddSingleton a no-op and hands
        // the argument and the container two different answers about one value.
        services.AddSingleton(TransmitterOptions with { Issuer = hostIssuer });
        services.AddSharedSignalsTransmitter(
            TransmitterOptions with { Issuer = "https://placeholder.example.com" });

        await using var provider = services.BuildServiceProvider();

        var stream = new StreamState
        {
            ReceiverId = "receiver-a",
            Status = StreamStatuses.Enabled,
            SubjectsMode = StreamSubjectsMode.None,
            Configuration = new StreamConfiguration
            {
                StreamId = "s-1",
                Issuer = hostIssuer,
                Audiences = ["https://receiver.example.com"],
                EventsDelivered = [],
                Delivery = new PollDeliveryMethod(new Uri("https://tr.example.com/ssf/poll/s-1")),
            },
        };

        Assert.True(await provider.GetRequiredService<IStreamStore>()
            .TryCreateAsync(stream, cancellationToken));

        await provider.GetRequiredService<EventDispatcher>().DispatchToStreamAsync(
            stream,
            new SecurityEventDescriptor
            {
                EventType = SharedSignalsEventTypes.StreamUpdated,
                Subject = new OpaqueSubject(stream.Configuration.StreamId),
                Payload = new StreamUpdatedEventPayload { Status = StreamStatuses.Enabled },
            },
            asStatusAnnouncement: true,
            cancellationToken);

        var minted = Assert.Single(signer.Signed);

        // Against the stream's own issuer as well as the literal: these two are the pair a receiver
        // compares, and the defect is precisely that they can differ.
        Assert.Equal(hostIssuer, minted.Issuer);
        Assert.Equal(stream.Configuration.Issuer, minted.Issuer);
    }

    private static IServiceCollection SecurityEventsBase()
    {
        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<ISecurityEventTokenSigner, FakeSigner>();
        services.AddSingleton<IIssuerKeyResolver, EmptyKeyResolver>();
        return services.AddSecurityEvents();
    }

    [Fact]
    public void Transmitter_ResolvesWhole_AndAHostStoreWins()
    {
        var services = SecurityEventsBase();
        var hostStore = new InMemoryStreamStore();
        services.AddSingleton<IStreamStore>(hostStore);

        using var provider = services
            .AddSharedSignalsTransmitter(TransmitterOptions)
            .BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<StreamManagementService>());
        Assert.NotNull(provider.GetRequiredService<EventDispatcher>());
        Assert.NotNull(provider.GetRequiredService<PollEndpointHandler>());
        Assert.NotNull(provider.GetRequiredService<PushDeliverySender>());
        Assert.Same(hostStore, provider.GetRequiredService<IStreamStore>());
    }

    /// <summary>
    /// The claim deciding which instance delivers a stream is a default like the stores, and it is
    /// the one a scaled-out deployment MUST replace - so a host's own must win here for the same
    /// reason and by the same rule.
    /// </summary>
    [Fact]
    public void Transmitter_ClaimsStreams_AndAHostLeaseWins()
    {
        var services = SecurityEventsBase();

        using var defaults = services
            .AddSharedSignalsTransmitter(TransmitterOptions)
            .BuildServiceProvider();

        Assert.IsType<ProcessLocalDeliveryLease>(defaults.GetRequiredService<IDeliveryLease>());

        var withHostLease = SecurityEventsBase();
        var hostLease = new ProcessLocalDeliveryLease(TimeProvider.System);
        withHostLease.AddSingleton<IDeliveryLease>(hostLease);

        using var provider = withHostLease
            .AddSharedSignalsTransmitter(TransmitterOptions)
            .BuildServiceProvider();

        Assert.Same(hostLease, provider.GetRequiredService<IDeliveryLease>());
    }

    [Fact]
    public void WithoutTheSecurityEventsCore_TheRoleRefuses_NamingThePrerequisite()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => new ServiceCollection().AddSharedSignalsTransmitter(TransmitterOptions));

        Assert.Contains("AddSecurityEvents", exception.Message);
    }

    [Fact]
    public async Task Receiver_RunsTheSharedSignalsSteps_InsideTheComposedPipeline()
    {
        // The proof is behavioral: a token carrying "sub" earns the Section 4.1.2 verdict only
        // ForbidSubStep produces, and it earns it BEFORE any signature work - the token below
        // has no valid signature, so reaching a signature error instead would mean the step is
        // ordered wrong, and reaching success would mean it is not wired at all.
        var services = SecurityEventsBase().AddSharedSignalsReceiver(new SharedSignalsValidationOptions
        {
            StreamIssuer = "https://tr.example.com",
        });
        services.AddSingleton<ISecurityEventSink, NullSink>();

        await using var provider = services.BuildServiceProvider();

        // Resolved from the receiver's own profile: no other validator family exists, and the
        // profile's key is the token kind this receiver validates.
        var validator = provider.GetRequiredKeyedService<ISecurityEventTokenValidator>(
            ValidationProfileKeys.SecurityEvent);

        var verdict = await validator.ValidateAsync(
            UnsignedToken(payload: """{"sub": "user-1", "events": {"urn:example": {}}}"""),
            provider.GetRequiredService<SharedSignalsValidationOptions>(),
            TestContext.Current.CancellationToken);

        Assert.True(verdict.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.TokenConfusion, error.Code);
        Assert.Contains("4.1.2", error.Description);
    }

    [Fact]
    public void Receiver_RegisteredTwice_AddsEachStepOnce()
    {
        var services = SecurityEventsBase();
        var options = new SharedSignalsValidationOptions();

        services.AddSharedSignalsReceiver(options).AddSharedSignalsReceiver(options);

        // The composed members are keyed descriptors, so the implementation type sits behind
        // the keyed property.
        Assert.Single(services, descriptor =>
            (descriptor.IsKeyedService
                ? descriptor.KeyedImplementationType
                : descriptor.ImplementationType) == typeof(ForbidSubStep));
    }

    private sealed class NullSink : ISecurityEventSink
    {
        public Task<DeliveryError?> ConsumeAsync(
            ValidatedSecurityEventToken token,
            CancellationToken cancellationToken = default)
            => Task.FromResult<DeliveryError?>(null);
    }

    private sealed class FakeSigner : ISecurityEventTokenSigner
    {
        public Task<string> SignAsync(SecurityEventToken token, CancellationToken cancellationToken = default)
            => Task.FromResult($"signed.{token.JwtId}");
    }

    private sealed class EmptyKeyResolver : IIssuerKeyResolver
    {
        public async IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
            string issuer,
            string? keyId = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.CompletedTask;
            yield break;
        }
    }

    /// <summary>
    /// A structurally valid, unsigned SET-shaped token: enough for the parse and the cheap
    /// unverified checks, nothing for the signature step.
    /// </summary>
    private static string UnsignedToken(string payload)
    {
        const string header = """{"typ": "secevent+jwt", "alg": "none"}""";
        return $"{Base64Url(header)}.{Base64Url(payload)}.";
    }

    private static string Base64Url(string json)
        => Convert.ToBase64String(Encoding.UTF8.GetBytes(JsonSerializer.Serialize(
                JsonSerializer.Deserialize<JsonElement>(json))))
            .TrimEnd('=')
            .Replace('+', '-')
            .Replace('/', '_');
}
