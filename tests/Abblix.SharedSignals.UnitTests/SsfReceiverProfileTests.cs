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

using System.Text.Json;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.SecurityEvents;
using Abblix.SecurityEvents.Subjects;
using Abblix.SecurityEvents.Validation;
using Abblix.SharedSignals.Receiver;
using Xunit;

namespace Abblix.SharedSignals.UnitTests;

/// <summary>
/// Pins the three SSF additions to the receiver profile: no "sub" (Section 4.1.2), the event
/// bound to its stream's issuer (Section 4.1.6), and the discard of events whose subject
/// carries an uninterpretable critical member (Section 3.6). Each step is driven through the
/// same context contract the composed pipeline drives it through.
/// </summary>
public class SsfReceiverProfileTests
{
    private const string StreamIssuer = "https://tr.example.com";

    private static SecurityEventToken BuildToken(Action<SecurityEventTokenBuilder>? customize = null)
    {
        var builder = new SecurityEventTokenBuilder()
            .WithIssuer(StreamIssuer)
            .WithJwtId("set-1")
            .WithEvent("https://example.com/events/test");
        customize?.Invoke(builder);
        return builder.Build();
    }

    /// <summary>
    /// A context in the state the pipeline reaches after the signature step, which is where the
    /// two trusted-claims steps under test declare they run.
    /// </summary>
    private static SecurityEventTokenValidationContext TrustedContext(
        SecurityEventToken token,
        SecurityEventTokenValidationOptions options)
    {
        var context = new SecurityEventTokenValidationContext("compact-not-under-test", options)
        {
            Token = token,
        };
        context.Establish(
            SecurityEventTokenValidationStates.Parsed | SecurityEventTokenValidationStates.SignatureVerified);
        return context;
    }

    [Fact]
    public async Task ForbidSub_PresenceOfSub_IsRejectedBeforeAnySignatureWork()
    {
        var jwt = new JsonWebToken();
        jwt.Payload.Subject = "user-1";

        var context = new SecurityEventTokenValidationContext(
            "compact-not-under-test", new SsfValidationOptions())
        {
            UnverifiedPayload = jwt.Payload,
        };
        context.Establish(SecurityEventTokenValidationStates.Parsed);

        var error = await new ForbidSubStep().ValidateAsync(context, TestContext.Current.CancellationToken);

        Assert.NotNull(error);
        Assert.Equal(SecurityEventTokenErrorCode.TokenConfusion, error.Code);
        Assert.Contains("4.1.2", error.Description);
    }

    [Fact]
    public async Task ForbidSub_AbsentSub_Passes()
    {
        var context = new SecurityEventTokenValidationContext(
            "compact-not-under-test", new SsfValidationOptions())
        {
            UnverifiedPayload = new JsonWebToken().Payload,
        };
        context.Establish(SecurityEventTokenValidationStates.Parsed);

        Assert.Null(await new ForbidSubStep().ValidateAsync(context, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task StreamIssuer_MatchingIssuer_Passes()
    {
        var context = TrustedContext(BuildToken(), new SsfValidationOptions { StreamIssuer = StreamIssuer });

        Assert.Null(await new StreamIssuerStep().ValidateAsync(context, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task StreamIssuer_OtherTrustedIssuer_IsRejected()
    {
        // The issuer may well be on the receiver's allowlist; the SSF rule is narrower - the
        // event must come from THE stream's issuer (Section 4.1.6), or events replay across
        // streams.
        var context = TrustedContext(
            BuildToken(), new SsfValidationOptions { StreamIssuer = "https://other.example.com" });

        var error = await new StreamIssuerStep().ValidateAsync(context, TestContext.Current.CancellationToken);

        Assert.NotNull(error);
        Assert.Equal(SecurityEventTokenErrorCode.UnknownIssuer, error.Code);
        Assert.Contains("4.1.6", error.Description);
    }

    [Fact]
    public async Task StreamIssuer_WithoutConfiguration_FailsLoudly_NamingTheOption()
    {
        // A missing expectation is the receiver's wiring bug: reported as a token error it would
        // reject every token while the logs blame the transmitters.
        var unconfigured = TrustedContext(BuildToken(), new SsfValidationOptions());
        var wrongFlavor = TrustedContext(BuildToken(), new SecurityEventTokenValidationOptions());

        foreach (var context in new[] { unconfigured, wrongFlavor })
        {
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(async () =>
                await new StreamIssuerStep().ValidateAsync(context, TestContext.Current.CancellationToken));

            Assert.Contains(nameof(SsfValidationOptions.StreamIssuer), exception.Message);
        }
    }

    [Fact]
    public async Task CriticalMembers_UninterpretableCriticalMember_DiscardsTheEvent()
    {
        var subject = new ComplexSubject
        {
            User = new EmailSubject("bar@example.com"),
            AdditionalMembers = new Dictionary<string, JsonElement>
            {
                ["workload"] = JsonSerializer.SerializeToElement(new { format = "opaque", id = "wl-42" }),
            },
        };
        var context = TrustedContext(
            BuildToken(builder => builder.WithSubjectId(subject)),
            new SsfValidationOptions { CriticalSubjectMembers = ["workload"] });

        var error = await new CriticalSubjectMembersStep()
            .ValidateAsync(context, TestContext.Current.CancellationToken);

        Assert.NotNull(error);
        Assert.Equal(SecurityEventTokenErrorCode.Custom, error.Code);
        Assert.Contains("workload", error.Description);
        Assert.Contains("3.6", error.Description);
    }

    [Fact]
    public async Task CriticalMembers_InterpretedCriticalMember_Passes()
    {
        // "user" is critical AND understood: it deserialized into the typed property, so the
        // receiver processes it and nothing calls for a discard.
        var context = TrustedContext(
            BuildToken(builder => builder.WithSubjectId(new ComplexSubject
            {
                User = new EmailSubject("bar@example.com"),
            })),
            new SsfValidationOptions { CriticalSubjectMembers = ["user"] });

        Assert.Null(await new CriticalSubjectMembersStep()
            .ValidateAsync(context, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CriticalMembers_SimpleSubject_AndAbsentSubject_Pass()
    {
        // Critical members bind members WITHIN a Complex Subject (Sections 3.6, 7.1); a simple
        // subject has none, and whether "sub_id" must be present at all is the event's rule.
        var options = new SsfValidationOptions { CriticalSubjectMembers = ["user"] };
        var step = new CriticalSubjectMembersStep();

        var simple = TrustedContext(
            BuildToken(builder => builder.WithSubjectId(new OpaqueSubject("stream-1"))), options);
        var absent = TrustedContext(BuildToken(), options);

        Assert.Null(await step.ValidateAsync(simple, TestContext.Current.CancellationToken));
        Assert.Null(await step.ValidateAsync(absent, TestContext.Current.CancellationToken));
    }

    [Fact]
    public async Task CriticalMembers_UnreadableSubjectId_IsRejected()
    {
        // A receiver that cannot even name the subject cannot process any member of it; the
        // proprietary format below is outside both the RFC 9493 registry and the SSF additions.
        var token = BuildToken();
        token.Token.Payload.Json[IanaClaimTypes.SubId] = new JsonObject
        {
            [SubjectMemberNames.Format] = "x-proprietary",
            ["reference"] = "abc",
        };
        var context = TrustedContext(token, new SsfValidationOptions());

        var error = await new CriticalSubjectMembersStep()
            .ValidateAsync(context, TestContext.Current.CancellationToken);

        Assert.NotNull(error);
        Assert.Equal(SecurityEventTokenErrorCode.Custom, error.Code);
    }
}
