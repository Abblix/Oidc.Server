using System.Security.Claims;
using System.Text.Json.Nodes;
using Abblix.Jwt;
using Abblix.Oidc.Server.Features.UserAuthentication;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;
using Moq;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

public class AuthenticationSchemeAdapterTests
{
	private readonly Mock<IHttpContextAccessor> _httpContextAccessor;
	private readonly DefaultHttpContext _httpContext;
	private readonly AuthenticationSchemeAdapter _adapter;

	public AuthenticationSchemeAdapterTests()
	{
		_httpContextAccessor = new Mock<IHttpContextAccessor>(MockBehavior.Strict);
		_httpContext = new DefaultHttpContext();
		_httpContextAccessor.Setup(x => x.HttpContext).Returns(_httpContext);

		_adapter = new AuthenticationSchemeAdapter(
			_httpContextAccessor.Object,
			CookieAuthenticationDefaults.AuthenticationScheme);
	}

	[Fact]
	public async Task SignInAsync_WithStringAdditionalClaim_SerializesCorrectly()
	{
		// Arrange - Reproduces the bug where JsonValue<string> couldn't be converted to JsonElement
		var authSession = new AuthSession(
			Subject: "user123",
			SessionId: "session456",
			AuthenticationTime: DateTimeOffset.UtcNow,
			IdentityProvider: "TestProvider")
		{
			AdditionalClaims = new JsonObject
			{
				["custom_string"] = JsonValue.Create("test value"),
				["custom_number"] = JsonValue.Create(42),
				["custom_bool"] = JsonValue.Create(true),
				["custom_array"] = new JsonArray("value1", "value2"),
				["custom_object"] = new JsonObject { ["nested"] = "value" }
			}
		};

		// Setup authentication service mock
		var authServiceMock = new Mock<IAuthenticationService>();
		authServiceMock
			.Setup(x => x.SignInAsync(
				It.IsAny<HttpContext>(),
				CookieAuthenticationDefaults.AuthenticationScheme,
				It.IsAny<ClaimsPrincipal>(),
				It.IsAny<AuthenticationProperties>()))
			.Returns(Task.CompletedTask)
			.Verifiable();

		_httpContext.RequestServices = new ServiceCollection()
			.AddSingleton(authServiceMock.Object)
			.BuildServiceProvider();

		// Act
		await _adapter.SignInAsync(authSession);

		// Assert
		authServiceMock.Verify(x => x.SignInAsync(
			_httpContext,
			CookieAuthenticationDefaults.AuthenticationScheme,
			It.Is<ClaimsPrincipal>(p => ValidatePrincipalClaims(p, authSession)),
			It.IsAny<AuthenticationProperties>()), Times.Once);
	}

	[Theory]
	[InlineData("string_value", "test", ClaimValueTypes.String)]
	[InlineData("long_value", 123L, ClaimValueTypes.Integer64)]
	[InlineData("double_value", 45.67, ClaimValueTypes.Double)]
	[InlineData("bool_value", true, ClaimValueTypes.Boolean)]
	public async Task SignInAsync_WithPrimitiveAdditionalClaim_StoresCorrectValueType(
		string claimType,
		object value,
		string expectedValueType)
	{
		// Arrange
		var authSession = new AuthSession(
			Subject: "user123",
			SessionId: "session456",
			AuthenticationTime: DateTimeOffset.UtcNow,
			IdentityProvider: "TestProvider")
		{
			AdditionalClaims = new JsonObject
			{
				[claimType] = JsonValue.Create(value)
			}
		};

		ClaimsPrincipal? capturedPrincipal = null;
		var authServiceMock = new Mock<IAuthenticationService>();
		authServiceMock
			.Setup(x => x.SignInAsync(
				It.IsAny<HttpContext>(),
				CookieAuthenticationDefaults.AuthenticationScheme,
				It.IsAny<ClaimsPrincipal>(),
				It.IsAny<AuthenticationProperties>()))
			.Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>(
				(_, _, principal, _) => capturedPrincipal = principal)
			.Returns(Task.CompletedTask);

		_httpContext.RequestServices = new ServiceCollection()
			.AddSingleton(authServiceMock.Object)
			.BuildServiceProvider();

		// Act
		await _adapter.SignInAsync(authSession);

		// Assert
		Assert.NotNull(capturedPrincipal);
		var claim = capturedPrincipal.FindFirst(claimType);
		Assert.NotNull(claim);
		Assert.Equal(expectedValueType, claim.ValueType);
	}

	[Fact]
	public async Task SignInAsync_WithComplexAdditionalClaim_StoresAsJsonString()
	{
		// Arrange
		var authSession = new AuthSession(
			Subject: "user123",
			SessionId: "session456",
			AuthenticationTime: DateTimeOffset.UtcNow,
			IdentityProvider: "TestProvider")
		{
			AdditionalClaims = new JsonObject
			{
				["array_claim"] = new JsonArray("val1", "val2"),
				["object_claim"] = new JsonObject { ["nested"] = "value" }
			}
		};

		ClaimsPrincipal? capturedPrincipal = null;
		var authServiceMock = new Mock<IAuthenticationService>();
		authServiceMock
			.Setup(x => x.SignInAsync(
				It.IsAny<HttpContext>(),
				CookieAuthenticationDefaults.AuthenticationScheme,
				It.IsAny<ClaimsPrincipal>(),
				It.IsAny<AuthenticationProperties>()))
			.Callback<HttpContext, string, ClaimsPrincipal, AuthenticationProperties>(
				(_, _, principal, _) => capturedPrincipal = principal)
			.Returns(Task.CompletedTask);

		_httpContext.RequestServices = new ServiceCollection()
			.AddSingleton(authServiceMock.Object)
			.BuildServiceProvider();

		// Act
		await _adapter.SignInAsync(authSession);

		// Assert
		Assert.NotNull(capturedPrincipal);

		var arrayClaim = capturedPrincipal.FindFirst("array_claim");
		Assert.NotNull(arrayClaim);
		Assert.Equal(ClaimValueTypes.String, arrayClaim.ValueType); // Complex types stored as JSON strings
		Assert.Equal("[\"val1\",\"val2\"]", arrayClaim.Value);

		var objectClaim = capturedPrincipal.FindFirst("object_claim");
		Assert.NotNull(objectClaim);
		Assert.Equal(ClaimValueTypes.String, objectClaim.ValueType);
		Assert.Equal("{\"nested\":\"value\"}", objectClaim.Value);
	}

	private static bool ValidatePrincipalClaims(ClaimsPrincipal principal, AuthSession authSession)
	{
		// Verify standard claims
		if (principal.FindFirstValue(JwtClaimTypes.Subject) != authSession.Subject)
			return false;

		if (principal.FindFirstValue(JwtClaimTypes.SessionId) != authSession.SessionId)
			return false;

		// Verify additional claims exist
		if (authSession.AdditionalClaims != null)
		{
			foreach (var (claimType, _) in authSession.AdditionalClaims)
			{
				if (principal.FindFirst(claimType) == null)
					return false;
			}
		}

		return true;
	}
}
