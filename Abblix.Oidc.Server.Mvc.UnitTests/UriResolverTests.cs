using Abblix.Oidc.Server.Mvc.Features.ConfigurableRoutes;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Options;
using Moq;

namespace Abblix.Oidc.Server.Mvc.UnitTests;

public class UriResolverTests
{
	private readonly Mock<IHttpContextAccessor> _httpContextAccessor;
	private readonly Mock<IUrlHelperFactory> _urlHelperFactory;
	private readonly UriResolver _uriResolver;
	private readonly DefaultHttpContext _httpContext;

	public UriResolverTests()
	{
		_httpContextAccessor = new Mock<IHttpContextAccessor>(MockBehavior.Strict);
		_urlHelperFactory = new Mock<IUrlHelperFactory>(MockBehavior.Strict);
		_uriResolver = new UriResolver(_httpContextAccessor.Object, _urlHelperFactory.Object);

		// Setup HttpContext with default request properties
		_httpContext = new DefaultHttpContext();
		_httpContext.Request.Scheme = "https";
		_httpContext.Request.Host = new HostString("example.com");
		_httpContext.Request.PathBase = "/app";

		// Initialize RequestServices with fallback convention (like production does)
		SetupConfiguration(null);

		_httpContextAccessor.Setup(x => x.HttpContext).Returns(_httpContext);
	}

	[Theory]
	[InlineData("~/images/logo.png", "https://example.com/app/images/logo.png")]
	[InlineData("~/content/site.css", "https://example.com/app/content/site.css")]
	[InlineData("images/logo.png", "https://example.com/images/logo.png")] // Relative to server root, not app
	public void Content_StaticPath_ReturnsAbsoluteUri(string path, string expectedUrl)
	{
		// Act
		var result = _uriResolver.Content(path);

		// Assert
		Assert.Equal(expectedUrl, result.ToString());
	}

	[Theory]
	[InlineData(Path.Authorize, "https://example.com/app/connect/authorize")]
	[InlineData(Path.Token, "https://example.com/app/connect/token")]
	[InlineData(Path.UserInfo, "https://example.com/app/connect/userinfo")]
	[InlineData(Path.EndSession, "https://example.com/app/connect/endsession")]
	[InlineData(Path.Configuration, "https://example.com/app/.well-known/openid-configuration")]
	[InlineData(Path.Keys, "https://example.com/app/.well-known/jwks")]
	public void Content_PathConstantWithDefaultValue_ReturnsAbsoluteUri(string pathConstant, string expectedUrl)
	{
		// Arrange - No configuration provided, should use default values
		SetupConfiguration(null);

		// Act
		var result = _uriResolver.Content(pathConstant);

		// Assert
		Assert.Equal(expectedUrl, result.ToString());
	}

	[Fact]
	public void Content_PathConstantWithConfiguredValue_ReturnsConfiguredUri()
	{
		// Arrange - Same structure as ConfigurableRouteConvention uses
		var configuration = new ConfigurationBuilder()
			.AddInMemoryCollection(new Dictionary<string, string?>
			{
				["route:authorize"] = "~/oauth/authorize",
				["route:token"] = "~/oauth/token"
			})
			.Build();

		SetupConfiguration(configuration);

		// Act
		var authorizeResult = _uriResolver.Content(Path.Authorize);
		var tokenResult = _uriResolver.Content(Path.Token);

		// Assert
		Assert.Equal("https://example.com/app/oauth/authorize", authorizeResult.ToString());
		Assert.Equal("https://example.com/app/oauth/token", tokenResult.ToString());
	}

	[Fact]
	public void Content_PathConstantWithNestedTemplate_ResolvesRecursively()
	{
		// Arrange
		var configuration = new ConfigurationBuilder()
			.AddInMemoryCollection(new Dictionary<string, string?>
			{
				["route:base"] = "~/custom-connect",
				["route:authorize"] = "[route:base]/authorize"
			})
			.Build();

		SetupConfiguration(configuration);

		// Act
		var result = _uriResolver.Content(Path.Authorize);

		// Assert
		Assert.Equal("https://example.com/app/custom-connect/authorize", result.ToString());
	}

	[Fact]
	public void Content_DifferentSchemeAndHost_ReturnsCorrectAbsoluteUri()
	{
		// Arrange
		_httpContext.Request.Scheme = "http";
		_httpContext.Request.Host = new HostString("localhost:5000");
		_httpContext.Request.PathBase = "";
		SetupConfiguration(null);

		// Act
		var result = _uriResolver.Content(Path.Authorize);

		// Assert
		Assert.Equal("http://localhost:5000/connect/authorize", result.ToString());
	}

	[Theory]
	[InlineData("https", "api.example.com", "/v1", Path.UserInfo, "https://api.example.com/v1/connect/userinfo")]
	[InlineData("http", "localhost", "", "~/static/file.js", "http://localhost/static/file.js")]
	[InlineData("https", "secure.app", "/base", "images/icon.png", "https://secure.app/images/icon.png")] // Relative to server root
	public void Content_VariousRequestConfigurations_ReturnsCorrectUri(
		string scheme,
		string host,
		string pathBase,
		string path,
		string expectedUrl)
	{
		// Arrange
		_httpContext.Request.Scheme = scheme;
		_httpContext.Request.Host = new HostString(host);
		_httpContext.Request.PathBase = pathBase;
		SetupConfiguration(null);

		// Act
		var result = _uriResolver.Content(path);

		// Assert
		Assert.Equal(expectedUrl, result.ToString());
	}

	[Fact]
	public void Content_CircularDependencyInRouteTemplate_ThrowsInvalidOperationException()
	{
		// Arrange
		var configuration = new ConfigurationBuilder()
			.AddInMemoryCollection(new Dictionary<string, string?>
			{
				["route:authorize"] = "[route:token]",
				["route:token"] = "[route:authorize]"
			})
			.Build();

		SetupConfiguration(configuration);

		// Act & Assert
		var exception = Assert.Throws<InvalidOperationException>(() =>
			_uriResolver.Content(Path.Authorize));

		Assert.Contains("Circular dependency", exception.Message);
	}

	[Fact]
	public void Content_RouteTemplateWithoutFallback_ThrowsInvalidOperationException()
	{
		// Arrange - Create a custom route template without fallback
		const string customTemplate = "[route:nonexistent]";
		SetupConfiguration(null);

		// Act & Assert
		var exception = Assert.Throws<InvalidOperationException>(() =>
			_uriResolver.Content(customTemplate));

		// ConfigurableRouteConvention uses message: "Can't resolve the route {token}"
		Assert.Contains("Can't resolve the route", exception.Message);
		Assert.Contains("nonexistent", exception.Message);
	}

	private void SetupConfiguration(IConfiguration? configuration)
	{
		var services = new ServiceCollection();

		if (configuration != null)
		{
			services.AddSingleton(configuration);

			// Register MvcOptions with ConfigurableRouteConvention
			var configSection = configuration.GetSection("route");
			services.Configure<MvcOptions>(options =>
			{
				options.Conventions.Add(new ConfigurableRouteConvention(Path.RoutePrefix, configSection));
			});
		}
		else
		{
			// Register fallback convention when no configuration
			services.Configure<MvcOptions>(options =>
			{
				options.Conventions.Add(new ConfigurableRouteConvention(Path.RoutePrefix));
			});
		}

		_httpContext.RequestServices = services.BuildServiceProvider();
	}
}
