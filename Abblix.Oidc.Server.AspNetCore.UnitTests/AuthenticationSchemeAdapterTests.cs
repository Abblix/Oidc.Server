using System.Security.Claims;
using System.Text.Json.Nodes;
using Abblix.Jwt;
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

	public AuthenticationSchemeAdapterTests()
	{
		_httpContextAccessor = new Mock<IHttpContextAccessor>(MockBehavior.Strict);
		_httpContext = new DefaultHttpContext();
		_httpContextAccessor.Setup(x => x.HttpContext).Returns(_httpContext);

		_adapter = new AuthenticationSchemeAdapter(_httpContextAccessor.Object, Scheme);
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
	/// and AuthenticateAsync reconstructs the <see cref="AuthSession"/> from exactly those — the round-trip the
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
		_httpContext.RequestServices = new ServiceCollection().AddSingleton(authService.Object).BuildServiceProvider();
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
		Assert.Equal(new[] { "admin", "user" }, roles.Select(n => (string)n!));
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
	public async Task RoundTrip_AmrAndAffectedClientIds_Preserved()
	{
		var input = Session() with
		{
			AuthenticationMethodReferences = new[] { "pwd", "otp" },
			AffectedClientIds = new[] { "client-a", "client-b" },
		};

		var result = await RoundTripAsync(input);

		Assert.Equal(new[] { "pwd", "otp" }, result!.AuthenticationMethodReferences);
		Assert.Equal(new[] { "client-a", "client-b" }, result.AffectedClientIds);
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
		var identity = new ClaimsIdentity(new[] { new Claim(JwtClaimTypes.Subject, "user") }, Scheme);
		SetupAuthenticate(new ClaimsPrincipal(identity));

		Assert.Null(await _adapter.AuthenticateAsync());
	}

	[Fact]
	public async Task AuthenticateAsync_CookieWithoutSubject_ReturnsNull()
	{
		var identity = new ClaimsIdentity(new[]
		{
			new Claim(JwtClaimTypes.SessionId, "s"),
			new Claim(JwtClaimTypes.AuthenticationTime, "1700000000"),
		}, Scheme);
		SetupAuthenticate(new ClaimsPrincipal(identity));

		Assert.Null(await _adapter.AuthenticateAsync());
	}

	[Fact]
	public async Task AuthenticateAsync_MalformedAuthenticationTime_ReturnsNull()
	{
		var identity = new ClaimsIdentity(new[]
		{
			new Claim(JwtClaimTypes.Subject, "user"),
			new Claim(JwtClaimTypes.SessionId, "s"),
			new Claim(JwtClaimTypes.AuthenticationTime, "not-a-number"),
		}, Scheme);
		SetupAuthenticate(new ClaimsPrincipal(identity));

		Assert.Null(await _adapter.AuthenticateAsync());
	}

	[Fact]
	public async Task AuthenticateAsync_OutOfRangeAuthenticationTime_ReturnsNull()
	{
		var identity = new ClaimsIdentity(new[]
		{
			new Claim(JwtClaimTypes.Subject, "user"),
			new Claim(JwtClaimTypes.SessionId, "s"),
			new Claim(JwtClaimTypes.AuthenticationTime, long.MaxValue.ToString(System.Globalization.CultureInfo.InvariantCulture)),
		}, Scheme);
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
