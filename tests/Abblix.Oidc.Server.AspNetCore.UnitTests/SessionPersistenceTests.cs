// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Claims;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Time.Testing;
using Moq;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests;

/// <summary>
/// A host states at sign-in whether the session survives a browser restart, and the cookie is written so: a first
/// sign-in stating nothing starts a browser session, a repeat sign-in of the same end user stating nothing keeps what
/// the session had, and only an explicit choice changes it.
/// </summary>
public class SessionPersistenceTests
{
    private const string Scheme = CookieAuthenticationDefaults.AuthenticationScheme;

    private static readonly DateTimeOffset ExpiresAt = DateTimeOffset.FromUnixTimeSeconds(1_900_000_000);

    private readonly DefaultHttpContext _httpContext = new();
    private readonly FakeTimeProvider _clock = new(DateTimeOffset.FromUnixTimeSeconds(1_800_000_000));
    private readonly AuthenticationSchemeAdapter _adapter;
    private ClaimsPrincipal? _cookie;
    private AuthenticationProperties? _cookieProperties;

    public SessionPersistenceTests()
    {
        var accessor = new Mock<IHttpContextAccessor>();
        accessor.Setup(x => x.HttpContext).Returns(_httpContext);

        var terminator = new Mock<IAuthSessionTerminator>();
        terminator
            .Setup(t => t.TerminateAsync(It.IsAny<string>(), It.IsAny<string>()))
            .ReturnsAsync((string sessionId, string subject) => new LogoutContext(sessionId, subject, "issuer"));

        var authentication = new Mock<IAuthenticationService>();
        authentication
            .Setup(x => x.SignInAsync(It.IsAny<HttpContext>(), Scheme, It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
            .Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>((_, _, principal, properties) =>
            {
                // The cookie handler stamps the moment it writes the cookie
                properties.IssuedUtc ??= _clock.GetUtcNow();
                _cookie = principal;
                _cookieProperties = properties;
            })
            .Returns(Task.CompletedTask);
        authentication
            .Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), Scheme))
            .ReturnsAsync(() => _cookie is null
                ? AuthenticateResult.NoResult()
                : AuthenticateResult.Success(new AuthenticationTicket(_cookie, _cookieProperties, Scheme)));
        _httpContext.RequestServices =
            new ServiceCollection().AddSingleton(authentication.Object).AddSingleton(TestTenantAccess.UnderMain).BuildServiceProvider();

        _adapter = new AuthenticationSchemeAdapter(
            accessor.Object,
            terminator.Object,
            _clock,
            Scheme);
    }

    private static AuthSession Session(string subject = "alice") => new(
        Subject: subject,
        SessionId: $"{subject}-session",
        AuthenticationTime: DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
        IdentityProvider: "TestProvider");

    /// <summary>Starts the next request on the same cookie.</summary>
    private void NextRequest() => _httpContext.Items.Clear();

    [Fact]
    public async Task AFirstSignInAskingForAPersistentSession_WritesACookieWithThatExpiry()
    {
        await _adapter.SignInAsync(Session() with { Persistence = SessionPersistence.Until(ExpiresAt) });

        Assert.Equal((true, ExpiresAt), (_cookieProperties!.IsPersistent, _cookieProperties.ExpiresUtc));
    }

    [Fact]
    public async Task AFirstSignInStatingNothing_WritesABrowserSessionCookie()
    {
        await _adapter.SignInAsync(Session());

        Assert.False(_cookieProperties!.IsPersistent);
        Assert.Null(_cookieProperties.ExpiresUtc);
    }

    /// <summary>
    /// The persistence a session was written with is what the next request reads, with its authentication time, so
    /// a check of the time since the last real sign-in treats a persistent session as it treats a browser one.
    /// </summary>
    [Fact]
    public async Task APersistentSession_IsReadBackWithItsExpiryAndAuthenticationTime()
    {
        await _adapter.SignInAsync(Session() with { Persistence = SessionPersistence.Until(ExpiresAt) });
        NextRequest();

        var read = await _adapter.AuthenticateAsync();

        Assert.Equal(ExpiresAt, Assert.IsType<SessionPersistence.Persistent>(read!.Persistence).ExpiresAt);
        Assert.Equal(Session().AuthenticationTime, read.AuthenticationTime);
    }

    /// <summary>
    /// A re-authentication or a step-up page never shows the choice, so a sign-in of the same end user stating nothing
    /// keeps the session persistent and as long as it was, counted from the repeat sign-in: kept with its old end and a
    /// new issue time instead, a handler renewing it with activity would renew it only by what was left.
    /// </summary>
    [Fact]
    public async Task ARepeatSignInStatingNothing_KeepsTheSessionsLength()
    {
        var length = TimeSpan.FromDays(14);
        await _adapter.SignInAsync(Session() with { Persistence = SessionPersistence.Until(_clock.GetUtcNow() + length) });
        NextRequest();
        _clock.Advance(TimeSpan.FromDays(13));

        var result = await _adapter.SignInAsync(Session());

        var renewedUntil = _clock.GetUtcNow() + length;
        Assert.Equal((true, renewedUntil), (_cookieProperties!.IsPersistent, _cookieProperties.ExpiresUtc));
        Assert.Equal(renewedUntil, Assert.IsType<SessionPersistence.Persistent>(result.Session.Persistence).ExpiresAt);
    }

    /// <summary>
    /// A handler that reports a persistent cookie with no expiry, as one keeping its tickets elsewhere may, is read as
    /// nothing stated, and a repeat sign-in leaves the expiry to that handler again.
    /// </summary>
    [Fact]
    public async Task APersistentCookieWithNoExpiry_IsWrittenAgainWithNone()
    {
        await _adapter.SignInAsync(Session() with { Persistence = SessionPersistence.Until(ExpiresAt) });
        _cookieProperties!.ExpiresUtc = null;
        NextRequest();

        Assert.Equal(SessionPersistence.Unstated, (await _adapter.AuthenticateAsync())!.Persistence);

        NextRequest();
        await _adapter.SignInAsync(Session());

        Assert.Equal((true, (DateTimeOffset?)null), (_cookieProperties!.IsPersistent, _cookieProperties.ExpiresUtc));
    }

    [Fact]
    public async Task ARepeatSignInWithAnExplicitChoice_ChangesIt()
    {
        await _adapter.SignInAsync(Session() with { Persistence = SessionPersistence.Until(ExpiresAt) });
        NextRequest();

        await _adapter.SignInAsync(Session() with { Persistence = SessionPersistence.BrowserSession });

        Assert.False(_cookieProperties!.IsPersistent);
        Assert.Null(_cookieProperties.ExpiresUtc);
    }

    /// <summary>
    /// Somebody else signing in over a persistent session starts their own: what the replaced end user chose is not
    /// theirs to inherit.
    /// </summary>
    [Fact]
    public async Task AnotherEndUserSigningInStatingNothing_StartsABrowserSession()
    {
        await _adapter.SignInAsync(Session("alice") with { Persistence = SessionPersistence.Until(ExpiresAt) });
        NextRequest();

        await _adapter.SignInAsync(Session("bob"));

        Assert.False(_cookieProperties!.IsPersistent);
    }
}
