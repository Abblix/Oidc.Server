// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using System.Security.Claims;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Abblix.Oidc.Server.AspNetCore.UnitTests;

public class AuthenticationSchemeAdapterTests
{
	private const string Scheme = CookieAuthenticationDefaults.AuthenticationScheme;

	private readonly Mock<IHttpContextAccessor> _httpContextAccessor;
	private readonly DefaultHttpContext _httpContext;
	private readonly AuthenticationSchemeAdapter _adapter;
	private readonly List<string> _calls = [];

	public AuthenticationSchemeAdapterTests()
	{
		_httpContextAccessor = new Mock<IHttpContextAccessor>(MockBehavior.Strict);
		_httpContext = new DefaultHttpContext();
		_httpContextAccessor.Setup(x => x.HttpContext).Returns(_httpContext);

		var terminator = new Mock<IAuthSessionTerminator>(MockBehavior.Strict);
		terminator
			.Setup(t => t.TerminateAsync(It.IsAny<string>(), It.IsAny<string>()))
			.Callback((string sessionId, string subject) => _calls.Add($"terminate {sessionId} {subject}"))
			.ReturnsAsync((string sessionId, string subject) => new LogoutContext(sessionId, subject, "issuer"));

		_adapter = new AuthenticationSchemeAdapter(_httpContextAccessor.Object, terminator.Object, Scheme);
	}

	private static AuthSession Session(JsonObject? additionalClaims = null, string identityProvider = "TestProvider") => new(
		Subject: "user123",
		SessionId: "session456",
		AuthenticationTime: DateTimeOffset.FromUnixTimeSeconds(1_700_000_000),
		IdentityProvider: identityProvider)
	{
		AdditionalClaims = additionalClaims,
	};

	/// <summary>
	/// Runs a full write→read cycle: SignInAsync builds the principal/properties the cookie handler would persist,
	/// and AuthenticateAsync reconstructs the <see cref="AuthSession"/> from exactly those - the round-trip the
	/// production flow performs across two requests.
	/// </summary>
	private async Task<AuthSession?> RoundTripAsync(AuthSession input)
	{
		ClaimsPrincipal? captured = null;
		AuthenticationProperties? capturedProps = null;

		var authService = new Mock<IAuthenticationService>();
		authService
			.Setup(x => x.SignInAsync(It.IsAny<HttpContext>(), Scheme, It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
			.Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>((_, _, p, props) =>
			{
				captured = p;
				capturedProps = props;
			})
			.Returns(Task.CompletedTask);
		authService
			.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), Scheme))
			.ReturnsAsync(() => captured is null
				? AuthenticateResult.NoResult()
				: AuthenticateResult.Success(new AuthenticationTicket(captured, capturedProps, Scheme)));

		_httpContext.RequestServices = new ServiceCollection().AddSingleton(authService.Object).BuildServiceProvider();

		await _adapter.SignInAsync(input);

		// Read on the next request, which parses the cookie instead of answering with the session just written.
		NextRequest();
		return await _adapter.AuthenticateAsync();
	}

	/// <summary>Sets up AuthenticateAsync to return the given principal, simulating an arbitrary cookie under the scheme.</summary>
	private void SetupAuthenticate(ClaimsPrincipal principal)
	{
		var authService = new Mock<IAuthenticationService>();
		authService
			.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), Scheme))
			.ReturnsAsync(AuthenticateResult.Success(new AuthenticationTicket(principal, null, Scheme)));
		_httpContext.RequestServices = new ServiceCollection().AddSingleton(authService.Object).BuildServiceProvider();
	}

	private void SetupSignIn()
	{
		var authService = new Mock<IAuthenticationService>();
		authService
			.Setup(x => x.SignInAsync(It.IsAny<HttpContext>(), Scheme, It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
			.Returns(Task.CompletedTask);
		authService
			.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), Scheme))
			.ReturnsAsync(AuthenticateResult.NoResult());
		_httpContext.RequestServices = new ServiceCollection().AddSingleton(authService.Object).BuildServiceProvider();
	}

	/// <summary>
	/// Keeps the principal each sign-in writes and hands it back to the next read, as one cookie across requests.
	/// </summary>
	private void SetupCookie()
	{
		ClaimsPrincipal? written = null;
		var authService = new Mock<IAuthenticationService>();
		authService
			.Setup(x => x.SignInAsync(It.IsAny<HttpContext>(), Scheme, It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
			.Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>((_, _, p, _) => written = p)
			.Returns(Task.CompletedTask);
		authService
			.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), Scheme))
			.ReturnsAsync(() => written is null
				? AuthenticateResult.NoResult()
				: AuthenticateResult.Success(new AuthenticationTicket(written, Scheme)));
		_httpContext.RequestServices = new ServiceCollection().AddSingleton(authService.Object).BuildServiceProvider();
	}

	// ---------- Signing in over a session ----------

	/// <summary>
	/// Starts the next request on the same cookie: what a request remembers of its own writes does not carry over.
	/// </summary>
	private void NextRequest() => _httpContext.Items.Clear();

	[Fact]
	public async Task SignInAsync_WithoutASession_WritesTheSessionGivenAndEndsNone()
	{
		SetupCookie();

		var result = await _adapter.SignInAsync(Session());

		Assert.Equal("session456", result.Session.SessionId);
		Assert.Empty(result.EndedSessions);
		Assert.Empty(_calls);
	}

	[Fact]
	public async Task SignInAsync_OverAnotherPersonsSession_EndsIt()
	{
		SetupCookie();
		await _adapter.SignInAsync(Session() with { Subject = "alice", SessionId = "alice-session" });
		NextRequest();

		var result = await _adapter.SignInAsync(Session() with { Subject = "bob", SessionId = "bob-session" });

		Assert.Equal("bob-session", result.Session.SessionId);
		var ended = Assert.Single(result.EndedSessions);
		Assert.Equal(("alice", "alice-session"), (ended.Subject, ended.SessionId));
		Assert.Equal(["terminate alice-session alice"], _calls);
		Assert.Equal("bob-session", (await _adapter.AuthenticateAsync())!.SessionId);
	}

	/// <summary>
	/// The replaced session is ended only once the new cookie is written, so a sign-in the scheme refuses signs
	/// nobody out.
	/// </summary>
	[Fact]
	public async Task SignInAsync_TheSchemeRefuses_EndsNothing()
	{
		SetupCookie();
		await _adapter.SignInAsync(Session() with { Subject = "alice", SessionId = "alice-session" });
		NextRequest();
		var refusing = new Mock<IAuthenticationService>();
		refusing
			.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), Scheme))
			.ReturnsAsync(await _httpContext.RequestServices.GetRequiredService<IAuthenticationService>()
				.AuthenticateAsync(_httpContext, Scheme));
		refusing
			.Setup(x => x.SignInAsync(It.IsAny<HttpContext>(), Scheme, It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
			.ThrowsAsync(new InvalidOperationException("the scheme refused"));
		_httpContext.RequestServices = new ServiceCollection().AddSingleton(refusing.Object).BuildServiceProvider();

		await Assert.ThrowsAsync<InvalidOperationException>(
			() => _adapter.SignInAsync(Session() with { Subject = "bob", SessionId = "bob-session" }));

		Assert.Empty(_calls);
	}

	[Fact]
	public async Task SignInAsync_OverTheSamePersonsSession_ContinuesItUnderItsIdentifier()
	{
		SetupCookie();
		await _adapter.SignInAsync(Session() with { SessionId = "first-session" });
		NextRequest();
		var reauthenticatedAt = DateTimeOffset.FromUnixTimeSeconds(1_800_000_000);

		var result = await _adapter.SignInAsync(
			Session() with { SessionId = "second-session", AuthenticationTime = reauthenticatedAt });

		Assert.Equal("first-session", result.Session.SessionId);
		Assert.Empty(result.EndedSessions);
		Assert.Empty(_calls);
		var written = await _adapter.AuthenticateAsync();
		Assert.Equal(("first-session", reauthenticatedAt), (written!.SessionId, written.AuthenticationTime));
	}

	/// <summary>
	/// Subjects are identifiers compared exactly, so two differing only in case are two people.
	/// </summary>
	[Fact]
	public async Task SignInAsync_OverASubjectDifferingOnlyInCase_EndsIt()
	{
		SetupCookie();
		await _adapter.SignInAsync(Session() with { Subject = "alice", SessionId = "first-session" });
		NextRequest();

		var result = await _adapter.SignInAsync(Session() with { Subject = "Alice", SessionId = "second-session" });

		Assert.Equal("second-session", result.Session.SessionId);
		Assert.Single(result.EndedSessions);
	}

	/// <summary>
	/// Within one request the scheme keeps answering with the cookie the request arrived with, so the session a
	/// sign-in replaces is the one this request wrote last.
	/// </summary>
	[Fact]
	public async Task SignInAsync_TwiceInOneRequest_EndsWhatTheFirstWrote()
	{
		SetupSignIn();

		await _adapter.SignInAsync(Session() with { Subject = "bob", SessionId = "bob-session" });
		var result = await _adapter.SignInAsync(Session() with { Subject = "carol", SessionId = "carol-session" });

		Assert.Equal("bob-session", Assert.Single(result.EndedSessions).SessionId);
		Assert.Equal(["terminate bob-session bob"], _calls);
	}

	/// <summary>
	/// After signing out, the request holds no session, whatever cookie it arrived with.
	/// </summary>
	[Fact]
	public async Task SignInAsync_AfterSignOutInTheSameRequest_EndsNothing()
	{
		SetupCookie();
		await _adapter.SignInAsync(Session() with { Subject = "alice", SessionId = "alice-session" });
		NextRequest();
		var cookie = _httpContext.RequestServices.GetRequiredService<IAuthenticationService>();
		var arrived = await cookie.AuthenticateAsync(_httpContext, Scheme);
		var signingOut = new Mock<IAuthenticationService>();
		signingOut.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), Scheme)).ReturnsAsync(arrived);
		signingOut.Setup(x => x.SignOutAsync(It.IsAny<HttpContext>(), Scheme, It.IsAny<AuthenticationProperties>()))
			.Returns(Task.CompletedTask);
		signingOut
			.Setup(x => x.SignInAsync(It.IsAny<HttpContext>(), Scheme, It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
			.Returns(Task.CompletedTask);
		_httpContext.RequestServices = new ServiceCollection().AddSingleton(signingOut.Object).BuildServiceProvider();

		await _adapter.SignOutAsync();
		var result = await _adapter.SignInAsync(Session() with { Subject = "bob", SessionId = "bob-session" });

		Assert.Empty(result.EndedSessions);
		Assert.Empty(_calls);
	}

	/// <summary>
	/// Reading the session in the request that signed in answers with the session written, the same answer the
	/// next sign-in in that request replaces.
	/// </summary>
	[Fact]
	public async Task AuthenticateAsync_AfterSignInInTheSameRequest_ReturnsTheSessionWritten()
	{
		SetupSignIn();

		var result = await _adapter.SignInAsync(Session() with { Subject = "bob", SessionId = "bob-session" });

		Assert.Same(result.Session, await _adapter.AuthenticateAsync());
		Assert.Equal([result.Session], await _adapter.GetAvailableAuthSessions().ToArrayAsync(TestContext.Current.CancellationToken));
	}

	[Fact]
	public async Task AuthenticateAsync_AfterSignOutInTheSameRequest_ReturnsNone()
	{
		SetupCookie();
		await _adapter.SignInAsync(Session() with { Subject = "alice", SessionId = "alice-session" });
		NextRequest();
		var arrived = await _httpContext.RequestServices.GetRequiredService<IAuthenticationService>()
			.AuthenticateAsync(_httpContext, Scheme);
		var signingOut = new Mock<IAuthenticationService>();
		signingOut.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), Scheme)).ReturnsAsync(arrived);
		signingOut.Setup(x => x.SignOutAsync(It.IsAny<HttpContext>(), Scheme, It.IsAny<AuthenticationProperties>()))
			.Returns(Task.CompletedTask);
		_httpContext.RequestServices = new ServiceCollection().AddSingleton(signingOut.Object).BuildServiceProvider();

		await _adapter.SignOutAsync();

		Assert.Null(await _adapter.AuthenticateAsync());
	}

	/// <summary>
	/// A sign-in the scheme refused wrote nothing, so a retry in the same request still replaces the session the
	/// request arrived with.
	/// </summary>
	[Fact]
	public async Task SignInAsync_RetriedAfterTheSchemeRefused_EndsTheArrivedSession()
	{
		SetupCookie();
		await _adapter.SignInAsync(Session() with { Subject = "alice", SessionId = "alice-session" });
		NextRequest();
		var arrived = await _httpContext.RequestServices.GetRequiredService<IAuthenticationService>()
			.AuthenticateAsync(_httpContext, Scheme);
		var refuseOnce = new Mock<IAuthenticationService>();
		refuseOnce.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), Scheme)).ReturnsAsync(arrived);
		refuseOnce
			.SetupSequence(x => x.SignInAsync(It.IsAny<HttpContext>(), Scheme, It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
			.ThrowsAsync(new InvalidOperationException("the scheme refused"))
			.Returns(Task.CompletedTask);
		_httpContext.RequestServices = new ServiceCollection().AddSingleton(refuseOnce.Object).BuildServiceProvider();

		await Assert.ThrowsAsync<InvalidOperationException>(
			() => _adapter.SignInAsync(Session() with { Subject = "bob", SessionId = "bob-session" }));
		var result = await _adapter.SignInAsync(Session() with { Subject = "bob", SessionId = "bob-session" });

		Assert.Equal("alice-session", Assert.Single(result.EndedSessions).SessionId);
		Assert.Equal(["terminate alice-session alice"], _calls);
	}

	/// <summary>
	/// Each scheme keeps its own cookie, so what one scheme wrote in a request says nothing about another's.
	/// </summary>
	[Fact]
	public async Task SignInAsync_UnderAnotherScheme_DoesNotSeeThisSchemesWrite()
	{
		const string otherScheme = "Other";
		var authService = new Mock<IAuthenticationService>();
		authService
			.Setup(x => x.SignInAsync(It.IsAny<HttpContext>(), It.IsAny<string>(), It.IsAny<ClaimsPrincipal>(), It.IsAny<AuthenticationProperties>()))
			.Returns(Task.CompletedTask);
		authService
			.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), It.IsAny<string>()))
			.ReturnsAsync(AuthenticateResult.NoResult());
		_httpContext.RequestServices = new ServiceCollection().AddSingleton(authService.Object).BuildServiceProvider();
		var other = new AuthenticationSchemeAdapter(
			_httpContextAccessor.Object, Mock.Of<IAuthSessionTerminator>(MockBehavior.Strict), otherScheme);

		await _adapter.SignInAsync(Session() with { Subject = "alice", SessionId = "alice-session" });
		var result = await other.SignInAsync(Session() with { Subject = "bob", SessionId = "bob-session" });

		Assert.Empty(result.EndedSessions);
	}

	[Fact]
	public async Task SignInAsync_TheSamePersonTwiceInOneRequest_KeepsTheFirstIdentifier()
	{
		SetupSignIn();

		await _adapter.SignInAsync(Session() with { SessionId = "first-session" });
		var result = await _adapter.SignInAsync(Session() with { SessionId = "second-session" });

		Assert.Equal("first-session", result.Session.SessionId);
		Assert.Empty(result.EndedSessions);
		Assert.Empty(_calls);
	}

	// ---------- Round-trip fidelity ----------

	[Fact]
	public async Task RoundTrip_PreservesStandardSessionFields()
	{
		var result = await RoundTripAsync(Session());

		Assert.NotNull(result);
		Assert.Equal("user123", result!.Subject);
		Assert.Equal("session456", result.SessionId);
		Assert.Equal(DateTimeOffset.FromUnixTimeSeconds(1_700_000_000), result.AuthenticationTime);
		Assert.Equal("TestProvider", result.IdentityProvider);
	}

	[Theory]
	[InlineData("a string")]
	[InlineData("true")]
	[InlineData("42")]
	public async Task RoundTrip_StringAdditionalClaim_StaysString(string value)
	{
		var result = await RoundTripAsync(Session(new JsonObject { ["s"] = JsonValue.Create(value) }));

		Assert.Equal(value, (string)result!.AdditionalClaims!["s"]!);
	}

	[Fact]
	public async Task RoundTrip_PrimitiveAdditionalClaims_PreserveValues()
	{
		var result = await RoundTripAsync(Session(new JsonObject
		{
			["b"] = JsonValue.Create(true),
			["i"] = JsonValue.Create(42),
			["l"] = JsonValue.Create(9_000_000_000L),
			["d"] = JsonValue.Create(45.67),
		}));

		var claims = result!.AdditionalClaims!;
		Assert.True(claims["b"]!.GetValue<bool>());
		Assert.Equal(42, claims["i"]!.GetValue<int>());
		Assert.Equal(9_000_000_000L, claims["l"]!.GetValue<long>());
		Assert.Equal(45.67, claims["d"]!.GetValue<double>());
	}

	[Fact]
	public async Task RoundTrip_ArrayAdditionalClaim_StaysJsonArray()
	{
		var result = await RoundTripAsync(Session(new JsonObject { ["roles"] = new JsonArray("admin", "user") }));

		var roles = Assert.IsType<JsonArray>(result!.AdditionalClaims!["roles"]);
		Assert.Equal(["admin", "user"], roles.Select(n => (string)n!));
	}

	[Fact]
	public async Task RoundTrip_ObjectAdditionalClaim_StaysJsonObject()
	{
		var result = await RoundTripAsync(Session(new JsonObject { ["address"] = new JsonObject { ["city"] = "Astana" } }));

		var address = Assert.IsType<JsonObject>(result!.AdditionalClaims!["address"]);
		Assert.Equal("Astana", (string)address["city"]!);
	}

	[Fact]
	public async Task RoundTrip_UnspecifiedDateTime_PreservesValueWithoutBakingLocalOffset()
	{
		// A DateTime with Kind=Unspecified must come back identical, not silently shifted by the server's local
		// offset (which DateTimeOffset.Parse would otherwise assume). Compared via the original's JSON form, so the
		// assertion is machine-independent while the bug (local-offset bake-in) makes the round-trip diverge.
		var dateTime = new DateTime(2009, 6, 15, 13, 45, 30, DateTimeKind.Unspecified);

		var result = await RoundTripAsync(Session(new JsonObject { ["ts"] = JsonValue.Create(dateTime) }));

		Assert.Equal(JsonValue.Create(dateTime).ToJsonString(), result!.AdditionalClaims!["ts"]!.ToJsonString());
	}

	[Fact]
	public async Task RoundTrip_DateTimeOffset_PreservesInstantAndOffset()
	{
		var value = new DateTimeOffset(2009, 6, 15, 13, 45, 30, TimeSpan.FromHours(-7));

		var result = await RoundTripAsync(Session(new JsonObject { ["ts"] = JsonValue.Create(value) }));

		Assert.Equal(JsonValue.Create(value).ToJsonString(), result!.AdditionalClaims!["ts"]!.ToJsonString());
	}

	[Fact]
	public async Task RoundTrip_Amr_Preserved()
	{
		var input = Session() with
		{
			AuthenticationMethodReferences = ["pwd", "otp"],
		};

		var result = await RoundTripAsync(input);

		Assert.Equal(["pwd", "otp"], result!.AuthenticationMethodReferences);
	}

	/// <summary>
	/// A cookie written by a release that kept the session's clients in the authentication properties still
	/// reads as the session it was, so upgrading does not sign every user out.
	/// </summary>
	[Fact]
	public async Task AuthenticateAsync_CookieCarryingAClientListProperty_StillReadsTheSession()
	{
		var identity = new ClaimsIdentity([
			new Claim(JwtClaimTypes.Subject, "user"),
			new Claim(JwtClaimTypes.SessionId, "s"),
			new Claim(JwtClaimTypes.AuthenticationTime, "1700000000")
		], "TestProvider");

		var properties = new AuthenticationProperties();
		properties.SetString("AffectedClientIds", "[\"client-a\"]");

		var authService = new Mock<IAuthenticationService>();
		authService
			.Setup(x => x.AuthenticateAsync(It.IsAny<HttpContext>(), Scheme))
			.ReturnsAsync(AuthenticateResult.Success(
				new AuthenticationTicket(new ClaimsPrincipal(identity), properties, Scheme)));
		_httpContext.RequestServices = new ServiceCollection().AddSingleton(authService.Object).BuildServiceProvider();

		var result = await _adapter.AuthenticateAsync();

		Assert.Equal("s", result?.SessionId);
	}

	[Fact]
	public async Task SignInAsync_AdditionalClaimCollidingWithReservedName_IsNotInjected()
	{
		// An AdditionalClaims entry keyed on a reserved/adapter-managed claim name must not overwrite or duplicate
		// the managed claim. After round-trip the reserved value stays the one the adapter set.
		var input = Session(new JsonObject { [JwtClaimTypes.Subject] = JsonValue.Create("attacker") });

		var result = await RoundTripAsync(input);

		Assert.Equal("user123", result!.Subject);
		Assert.True(result.AdditionalClaims is null || !result.AdditionalClaims.ContainsKey(JwtClaimTypes.Subject));
	}

	// ---------- Robustness: a foreign/malformed cookie under the same scheme is "no session", not a 500 ----------

	[Fact]
	public async Task AuthenticateAsync_CookieWithoutSessionId_ReturnsNull()
	{
		// A plain host login cookie under the shared "Cookies" scheme: it has sub but no OIDC sid/auth_time.
		var identity = new ClaimsIdentity([new Claim(JwtClaimTypes.Subject, "user")], Scheme);
		SetupAuthenticate(new ClaimsPrincipal(identity));

		Assert.Null(await _adapter.AuthenticateAsync());
	}

	[Fact]
	public async Task AuthenticateAsync_CookieWithoutSubject_ReturnsNull()
	{
		var identity = new ClaimsIdentity([
			new Claim(JwtClaimTypes.SessionId, "s"),
			new Claim(JwtClaimTypes.AuthenticationTime, "1700000000")
		], Scheme);
		SetupAuthenticate(new ClaimsPrincipal(identity));

		Assert.Null(await _adapter.AuthenticateAsync());
	}

	[Fact]
	public async Task AuthenticateAsync_MalformedAuthenticationTime_ReturnsNull()
	{
		var identity = new ClaimsIdentity([
			new Claim(JwtClaimTypes.Subject, "user"),
			new Claim(JwtClaimTypes.SessionId, "s"),
			new Claim(JwtClaimTypes.AuthenticationTime, "not-a-number")
		], Scheme);
		SetupAuthenticate(new ClaimsPrincipal(identity));

		Assert.Null(await _adapter.AuthenticateAsync());
	}

	[Fact]
	public async Task AuthenticateAsync_OutOfRangeAuthenticationTime_ReturnsNull()
	{
		var identity = new ClaimsIdentity([
			new Claim(JwtClaimTypes.Subject, "user"),
			new Claim(JwtClaimTypes.SessionId, "s"),
			new Claim(JwtClaimTypes.AuthenticationTime, long.MaxValue.ToString(System.Globalization.CultureInfo.InvariantCulture))
		], Scheme);
		SetupAuthenticate(new ClaimsPrincipal(identity));

		Assert.Null(await _adapter.AuthenticateAsync());
	}

	[Fact]
	public async Task AuthenticateAsync_NotAuthenticated_ReturnsNull()
	{
		SetupAuthenticate(new ClaimsPrincipal(new ClaimsIdentity()));

		Assert.Null(await _adapter.AuthenticateAsync());
	}

	// ---------- Fail-fast: an empty IdentityProvider would produce an unreadable session (silent login loop) ----------

	[Fact]
	public async Task SignInAsync_EmptyIdentityProvider_Throws()
	{
		SetupSignIn();

		await Assert.ThrowsAsync<ArgumentException>(() => _adapter.SignInAsync(Session(identityProvider: "")));
	}

	[Fact]
	public async Task SignInAsync_NonEmptyIdentityProvider_DoesNotThrow()
	{
		SetupSignIn();

		var exception = await Record.ExceptionAsync(() => _adapter.SignInAsync(Session()));
		Assert.Null(exception);
	}
}
