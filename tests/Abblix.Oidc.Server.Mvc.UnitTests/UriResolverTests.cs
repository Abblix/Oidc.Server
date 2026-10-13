// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: LicenseRef-Abblix-EULA
//
// This software is provided 'as-is', without any express or implied warranty.
// Licensing terms, including free-of-charge use, are stated in LICENSE.md
// in the official repository at https://github.com/Abblix/Oidc.Server

using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc.Routing;
using Microsoft.Extensions.DependencyInjection;
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

	private UriResolver CreateResolver() => new(_httpContextAccessor.Object, _urlHelperFactory.Object);

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

	[Fact]
	public void Content_DifferentSchemeAndHost_ReturnsCorrectAbsoluteUri()
	{
		// Arrange
		_httpContext.Request.Scheme = "http";
		_httpContext.Request.Host = new HostString("localhost:5000");
		_httpContext.Request.PathBase = "";
		var resolver = CreateResolver();

		// Act
		var result = resolver.Content("~/connect/authorize");

		// Assert
		Assert.Equal("http://localhost:5000/connect/authorize", result.ToString());
	}

	[Theory]
	[InlineData("https", "api.example.com", "/v1", "~/connect/userinfo", "https://api.example.com/v1/connect/userinfo")]
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
}
