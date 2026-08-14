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
using Abblix.SharedSignals.Transmitter;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the wiring: each role resolves whole from one call over the Security Events core, a
/// host pre-registration wins over the package default, the missing prerequisite fails loudly
/// naming it, and the SSF profile steps actually RUN inside the composed pipeline - proven by
/// a verdict only they produce, not by their registrations existing.
/// </summary>
public class SsfServiceCollectionTests
{
    private static SsfTransmitterOptions TransmitterOptions => new()
    {
        Issuer = "https://tr.example.com",
        PollEndpointFactory = streamId => new Uri($"https://tr.example.com/ssf/poll/{streamId}"),
    };

    /// <summary>
    /// The Security Events core plus the two deployment-knowledge seams a real host wires with
    /// keys - faked here, because these tests measure wiring, not cryptography.
    /// </summary>
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
            .AddSsfTransmitter(TransmitterOptions)
            .BuildServiceProvider();

        Assert.NotNull(provider.GetRequiredService<StreamManagementService>());
        Assert.NotNull(provider.GetRequiredService<EventDispatcher>());
        Assert.NotNull(provider.GetRequiredService<PollEndpointHandler>());
        Assert.NotNull(provider.GetRequiredService<PushDeliverySender>());
        Assert.Same(hostStore, provider.GetRequiredService<IStreamStore>());
    }

    [Fact]
    public void WithoutTheSecurityEventsCore_TheRoleRefuses_NamingThePrerequisite()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => new ServiceCollection().AddSsfTransmitter(TransmitterOptions));

        Assert.Contains("AddSecurityEvents", exception.Message);
    }

    [Fact]
    public async Task Receiver_RunsTheSsfSteps_InsideTheComposedPipeline()
    {
        // The proof is behavioral: a token carrying "sub" earns the Section 4.1.2 verdict only
        // ForbidSubStep produces, and it earns it BEFORE any signature work - the token below
        // has no valid signature, so reaching a signature error instead would mean the step is
        // ordered wrong, and reaching success would mean it is not wired at all.
        var services = SecurityEventsBase().AddSsfReceiver(new SsfValidationOptions
        {
            StreamIssuer = "https://tr.example.com",
        });
        services.AddSingleton<ISecurityEventSink, NullSink>();

        await using var provider = services.BuildServiceProvider();
        var validator = provider.GetRequiredService<ISecurityEventTokenValidator>();

        var verdict = await validator.ValidateAsync(
            UnsignedToken(payload: """{"sub": "user-1", "events": {"urn:example": {}}}"""),
            provider.GetRequiredService<SsfValidationOptions>(),
            TestContext.Current.CancellationToken);

        Assert.True(verdict.TryGetFailure(out var error));
        Assert.Equal(SecurityEventTokenErrorCode.TokenConfusion, error.Code);
        Assert.Contains("4.1.2", error.Description);
    }

    [Fact]
    public void Receiver_RegisteredTwice_AddsEachStepOnce()
    {
        var services = SecurityEventsBase();
        var options = new SsfValidationOptions();

        services.AddSsfReceiver(options).AddSsfReceiver(options);

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
