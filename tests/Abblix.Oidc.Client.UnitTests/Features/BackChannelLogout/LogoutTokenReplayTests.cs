// Abblix OIDC Client Library
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

using Abblix.Jwt;
using Abblix.Oidc.Client.Features.BackChannelLogout;
using Microsoft.Extensions.Time.Testing;

namespace Abblix.Oidc.Client.UnitTests.Features.BackChannelLogout;

/// <summary>
/// Step 8 of section 2.6, and the memory that makes it possible.
/// </summary>
public class LogoutTokenReplayTests
{
    private const string Issuer = "https://provider.example.com";

    private static readonly DateTimeOffset Now = new(2026, 7, 21, 12, 0, 0, TimeSpan.Zero);

    private static (ILogoutTokenReplayGuard Guard, FakeTimeProvider Clock) Create()
    {
        var clock = new FakeTimeProvider(Now);
        return (new InMemoryLogoutTokenReplayGuard(clock), clock);
    }

    /// <summary>
    /// The first sighting of a token is recorded and allowed through.
    /// </summary>
    [Fact]
    public async Task AFirstSightingIsAllowed()
    {
        var (guard, _) = Create();

        Assert.True(await guard.TryRecordAsync(
            "the-token", Now.AddMinutes(2), TestContext.Current.CancellationToken));
    }

    /// <summary>
    /// The second is refused. Anyone who observed the first can post it again inside the window section 4
    /// asks providers to use, and nothing but this record tells the two apart.
    /// </summary>
    [Fact]
    public async Task ASecondSightingIsRefused()
    {
        var (guard, _) = Create();
        var cancellationToken = TestContext.Current.CancellationToken;

        await guard.TryRecordAsync("the-token", Now.AddMinutes(2), cancellationToken);

        Assert.False(await guard.TryRecordAsync("the-token", Now.AddMinutes(2), cancellationToken));
    }

    /// <summary>
    /// Two different tokens do not shadow each other.
    /// </summary>
    [Fact]
    public async Task AnotherTokenIsUnaffected()
    {
        var (guard, _) = Create();
        var cancellationToken = TestContext.Current.CancellationToken;

        await guard.TryRecordAsync("one-token", Now.AddMinutes(2), cancellationToken);

        Assert.True(await guard.TryRecordAsync("another-token", Now.AddMinutes(2), cancellationToken));
    }

    /// <summary>
    /// A record is forgotten once the token it describes can no longer be used, so the memory does not grow
    /// for the life of the process.
    /// </summary>
    /// <remarks>
    /// Observed through behaviour rather than by counting entries: a token identifier that could somehow be
    /// reused after its window is not a replay, because the expiry check refuses that token before the guard
    /// is reached.
    /// </remarks>
    [Fact]
    public async Task ARecordIsForgottenOnceItsTokenExpires()
    {
        var (guard, clock) = Create();
        var cancellationToken = TestContext.Current.CancellationToken;

        await guard.TryRecordAsync("the-token", Now.AddMinutes(2), cancellationToken);
        clock.Advance(TimeSpan.FromMinutes(3));

        Assert.True(await guard.TryRecordAsync(
            "the-token", clock.GetUtcNow().AddMinutes(2), cancellationToken));
    }

    /// <summary>
    /// Steps 9 to 11: a notification is matched against a session this client holds.
    /// </summary>
    [Fact]
    public void ANotificationMatchesItsOwnSession()
    {
        var notification = new LogoutNotification(Issuer, "the-subject", "the-session", "the-token");

        Assert.True(notification.Matches(IdentityToken(Issuer, "the-subject", "the-session")));
    }

    /// <summary>
    /// Another issuer's notification is about no session of this provider's, however well it matches
    /// otherwise.
    /// </summary>
    [Fact]
    public void AnotherIssuerDoesNotMatch()
    {
        var notification = new LogoutNotification(
            "https://elsewhere.example.com", "the-subject", "the-session", "the-token");

        Assert.False(notification.Matches(IdentityToken(Issuer, "the-subject", "the-session")));
    }

    /// <summary>
    /// A different subject, and a different session, each fail on their own.
    /// </summary>
    [Theory]
    [InlineData("somebody-else", "the-session")]
    [InlineData("the-subject", "another-session")]
    public void ADifferentSessionDoesNotMatch(string subject, string sessionId)
    {
        var notification = new LogoutNotification(Issuer, subject, sessionId, "the-token");

        Assert.False(notification.Matches(IdentityToken(Issuer, "the-subject", "the-session")));
    }

    /// <summary>
    /// A notification naming only a subject is about every session this client holds for that user, which is
    /// what a provider means by omitting the session identifier.
    /// </summary>
    [Fact]
    public void ASubjectOnlyNotificationMatchesEverySessionOfThatUser()
    {
        var notification = new LogoutNotification(Issuer, "the-subject", null, "the-token");

        Assert.True(notification.Matches(IdentityToken(Issuer, "the-subject", "one-session")));
        Assert.True(notification.Matches(IdentityToken(Issuer, "the-subject", "another-session")));
        Assert.False(notification.Matches(IdentityToken(Issuer, "somebody-else", "one-session")));
    }

    private static JsonWebToken IdentityToken(string issuer, string subject, string sessionId)
    {
        var token = new JsonWebToken();
        token.Payload.Issuer = issuer;
        token.Payload.Subject = subject;
        token.Payload.SessionId = sessionId;
        return token;
    }
}
