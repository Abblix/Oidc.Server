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
	private readonly DefaultHttpContext _httpContext;

	public UriResolverTests()
	{
		_httpContextAccessor = new Mock<IHttpContextAccessor>(MockBehavior.Strict);
		_urlHelperFactory = new Mock<IUrlHelperFactory>(MockBehavior.Strict);

		// Setup HttpContext with default request properties
		_httpContext = new DefaultHttpContext();
		_httpContext.Request.Scheme = "https";
		_httpContext.Request.Host = new HostString("example.com");
		_httpContext.Request.PathBase = "/app";

		// Setup RequestServices with empty service provider
		_httpContext.RequestServices = new ServiceCollection().BuildServiceProvider();

		_httpContextAccessor.Setup(x => x.HttpContext).Returns(_httpContext);
	}

	private UriResolver CreateResolver(IConfigurationSection? configSection = null)
	{
		var services = new ServiceCollection();

		// Configure MVC options with ConfigurableRouteConvention if configSection is provided
		services.Configure<MvcOptions>(options =>
		{
			if (configSection != null)
			{
				options.Conventions.Add(new ConfigurableRouteConvention(Path.RoutePrefix, configSection));
			}
		});

		_httpContext.RequestServices = services.BuildServiceProvider();

		var mvcOptions = _httpContext.RequestServices.GetRequiredService<IOptions<MvcOptions>>();
		return new UriResolver(_httpContextAccessor.Object, _urlHelperFactory.Object, mvcOptions);
	}

	[Theory]
	[InlineData("~/images/logo.png", "https://example.com/app/images/logo.png")]
	[InlineData("~/content/site.css", "https://example.com/app/content/site.css")]
	[InlineData("images/logo.png", "https://example.com/images/logo.png")] // Relative to server root, not app
	public void Content_StaticPath_ReturnsAbsoluteUri(string path, string expectedUrl)
	{
		// Arrange
		var resolver = CreateResolver();

		// Act
		var result = resolver.Content(path);

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
		var resolver = CreateResolver();

		// Act
		var result = resolver.Content(pathConstant);

		// Assert
		Assert.Equal(expectedUrl, result.ToString());
	}

	[Fact]
	public void Content_PathConstantWithConfiguredValue_ReturnsConfiguredUri()
	{
		// Arrange
		var configuration = new ConfigurationBuilder()
			.AddInMemoryCollection(new Dictionary<string, string?>
			{
				["Routes:authorize"] = "~/oauth/authorize",
				["Routes:token"] = "~/oauth/token"
			})
			.Build();

		var configSection = configuration.GetSection("Routes");
		var resolver = CreateResolver(configSection);

		// Act
		var authorizeResult = resolver.Content(Path.Authorize);
		var tokenResult = resolver.Content(Path.Token);

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
				["Routes:base"] = "~/custom-connect",
				["Routes:authorize"] = "[route:base]/authorize"
			})
			.Build();

		var configSection = configuration.GetSection("Routes");
		var resolver = CreateResolver(configSection);

		// Act
		var result = resolver.Content(Path.Authorize);

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
		var resolver = CreateResolver();

		// Act
		var result = resolver.Content(Path.Authorize);

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
		var resolver = CreateResolver();

		// Act
		var result = resolver.Content(path);

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
				["Routes:authorize"] = "[route:token]",
				["Routes:token"] = "[route:authorize]"
			})
			.Build();

		var configSection = configuration.GetSection("Routes");
		var resolver = CreateResolver(configSection);

		// Act & Assert
		var exception = Assert.Throws<InvalidOperationException>(() =>
			resolver.Content(Path.Authorize));

		Assert.Contains("Circular dependency", exception.Message);
	}

	[Fact]
	public void Content_RouteTemplateWithoutFallback_ThrowsInvalidOperationException()
	{
		// Arrange - Create a custom route template without fallback
		const string customTemplate = "[route:nonexistent]";
		var resolver = CreateResolver();

		// Act & Assert
		var exception = Assert.Throws<InvalidOperationException>(() =>
			resolver.Content(customTemplate));

		Assert.Contains("Can't resolve the route", exception.Message);
		Assert.Contains("nonexistent", exception.Message);
	}
}
