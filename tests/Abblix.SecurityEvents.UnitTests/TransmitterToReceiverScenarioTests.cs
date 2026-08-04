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
using System.Text.Json;
using System.Text.Json.Serialization;
using Abblix.Jwt;
using Abblix.Jwt.ReplayPrevention;
using Abblix.SecurityEvents.Abstractions;
using Abblix.SecurityEvents.Events;
using Abblix.SecurityEvents.Infrastructure;
using Abblix.SecurityEvents.Subjects;
using Abblix.SecurityEvents.Validation;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Time.Testing;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// The remaining two consumers of the plan's readiness criterion, run as one story over real
/// cryptography: a tenant transmitter emitting its custom membership event, and a receiver
/// validating, guarding against replay, and processing idempotently. Everything a real pair would
/// do happens here - typed payload with an RFC 9493 subject, RS256 signature through the core,
/// the full default pipeline, the replay cache deciding process-versus-acknowledge - so a green
/// run means the public API carried both consumers without the core needing another line.
/// </summary>
public class TransmitterToReceiverScenarioTests
{
    private const string TenantIssuer = "https://tenant.example.com";
    private const string ReceiverAudience = "https://receiver.example.com/ssf/events";
    private const string MembershipChanged = "https://tenant.example.com/events/membership-changed";

    private static readonly DateTimeOffset Now = DateTimeOffset.FromUnixTimeSeconds(1754040000);

    /// <summary>
    /// The tenant's own event payload, exactly as the architecture sketches it: the subject named
    /// by an RFC 9493 identifier pointing at the account issuer, plus the tenant's business
    /// members.
    /// </summary>
    private sealed class MembershipChangedPayload : IEventPayload
    {
        [JsonPropertyName("subject")]
        public required SubjectIdentifier Subject { get; init; }

        [JsonPropertyName("tenant_id")]
        public required string TenantId { get; init; }

        [JsonPropertyName("change")]
        public required string Change { get; init; }
    }

    private sealed class FixedKeyResolver(params JsonWebKey[] keys) : IIssuerKeyResolver
    {
        public async IAsyncEnumerable<JsonWebKey> ResolveSigningKeysAsync(
            string issuer,
            string? keyId = null,
            [EnumeratorCancellation] CancellationToken cancellationToken = default)
        {
            await Task.Yield();
            foreach (var key in keys)
            {
                yield return key;
            }
        }
    }

    private static ServiceProvider BuildPair()
    {
        JsonWebKey key = JsonWebKeyFactory.CreateRsa(PublicKeyUsages.Signature, SigningAlgorithms.RS256);

        var services = new ServiceCollection();
        services.AddLogging();
        services.AddSingleton<TimeProvider>(new FakeTimeProvider(Now));
        services.AddSingleton<IIssuerKeyResolver>(new FixedKeyResolver(key));
        services.AddSecurityEvents(options =>
        {
            options.SigningKeySource = _ => Task.FromResult(key);
            options.Events.Register<MembershipChangedPayload>(MembershipChanged);
        });
        services.AddDistributedMemoryCache();
        services.AddDistributedReplayCache();

        return services.BuildServiceProvider();
    }

    private static async Task<string> TransmitMembershipRevocation(IServiceProvider transmitter)
        => await new SecurityEventTokenBuilder()
            .WithIssuer(TenantIssuer)
            .WithAudience(ReceiverAudience)
            .WithJwtId("evt-8f3a")
            .WithIssuedAt(Now)
            .WithEvent(
                MembershipChanged,
                new MembershipChangedPayload
                {
                    Subject = new IssSubSubject("https://account.example.com", "a3f1c9e2"),
                    TenantId = "t-acme",
                    Change = "revoked",
                })
            .SignAsync(
                transmitter.GetRequiredService<ISecurityEventTokenSigner>(),
                TestContext.Current.CancellationToken);

    /// <summary>
    /// The receiver's whole handling of one delivery, in the order the design fixes: validate,
    /// then register the identifier, then act - and act only when the identifier was new, because
    /// a transmitter may deliver the same SET again and processing is idempotent by contract.
    /// </summary>
    private static async Task<bool> ReceiveAndProcess(
        IServiceProvider receiver,
        string compact,
        List<MembershipChangedPayload> processed)
    {
        var result = await receiver.GetRequiredService<ISecurityEventTokenValidator>().ValidateAsync(
            compact,
            new SecurityEventTokenValidationOptions
            {
                ExpectedAudience = ReceiverAudience,
                ExpectedIssuers = [TenantIssuer],
            },
            TestContext.Current.CancellationToken);

        Assert.True(result.TryGetSuccess(out var validated), "Validation unexpectedly failed.");

        var token = validated.Token;
        var isFirstDelivery = await receiver.GetRequiredService<IReplayCache>().TryReserveAsync(
            $"{token.Issuer}:{token.JwtId}",
            token.IssuedAt!.Value + TimeSpan.FromMinutes(10),
            TestContext.Current.CancellationToken);

        if (isFirstDelivery)
        {
            processed.Add(Assert.IsType<MembershipChangedPayload>(validated.EventPayloads![MembershipChanged]));
        }

        // Acknowledged either way: a repeat is not a protocol error, and the transmitter is owed
        // the acknowledgement that releases it from retaining the SET.
        return isFirstDelivery;
    }

    [Fact]
    public async Task OneEvent_DeliveredTwice_ProcessesOnce_AcknowledgesTwice()
    {
        await using var pair = BuildPair();
        var processed = new List<MembershipChangedPayload>();

        var compact = await TransmitMembershipRevocation(pair);

        var firstDelivery = await ReceiveAndProcess(pair, compact, processed);
        var redelivery = await ReceiveAndProcess(pair, compact, processed);

        Assert.True(firstDelivery);
        Assert.False(redelivery);

        var payload = Assert.Single(processed);
        Assert.Equal("t-acme", payload.TenantId);
        Assert.Equal("revoked", payload.Change);

        var subject = Assert.IsType<IssSubSubject>(payload.Subject);
        Assert.Equal("https://account.example.com", subject.Issuer);
        Assert.Equal("a3f1c9e2", subject.Subject);
    }

    [Fact]
    public async Task TwoDistinctEvents_BothProcess()
    {
        await using var pair = BuildPair();
        var processed = new List<MembershipChangedPayload>();

        var first = await TransmitMembershipRevocation(pair);
        var second = await new SecurityEventTokenBuilder()
            .WithIssuer(TenantIssuer)
            .WithAudience(ReceiverAudience)
            .WithJwtId("evt-9b4c")
            .WithIssuedAt(Now)
            .WithEvent(
                MembershipChanged,
                new MembershipChangedPayload
                {
                    Subject = new IssSubSubject("https://account.example.com", "b7d2e0f1"),
                    TenantId = "t-globex",
                    Change = "suspended",
                })
            .SignAsync(
                pair.GetRequiredService<ISecurityEventTokenSigner>(),
                TestContext.Current.CancellationToken);

        Assert.True(await ReceiveAndProcess(pair, first, processed));
        Assert.True(await ReceiveAndProcess(pair, second, processed));

        Assert.Equal(2, processed.Count);
    }

    [Fact]
    public async Task TheWirePayload_IsTheArchitectureDocumentShape()
    {
        // The claims set the architecture document sketches for the membership event, verified as
        // the actual wire bytes: the subject travels as an RFC 9493 identifier, not as anybody's
        // internal key.
        await using var pair = BuildPair();

        var compact = await TransmitMembershipRevocation(pair);
        var payloadSegment = compact.Split('.')[1];
        var claims = JsonDocument.Parse(
            Convert.FromBase64String(payloadSegment.Replace('-', '+').Replace('_', '/')
                .PadRight((payloadSegment.Length + 3) & ~3, '=')));

        var statement = claims.RootElement
            .GetProperty(JwtClaimTypes.Events)
            .GetProperty(MembershipChanged);

        Assert.Equal("iss_sub", statement.GetProperty("subject").GetProperty("format").GetString());
        Assert.Equal("t-acme", statement.GetProperty("tenant_id").GetString());
        Assert.Equal("revoked", statement.GetProperty("change").GetString());
    }
}
