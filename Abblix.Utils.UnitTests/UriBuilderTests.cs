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

using Microsoft.AspNetCore.Http;

namespace Abblix.Utils.UnitTests;

/// <summary>
/// Tests for the <see cref="UriBuilder"/> class, verifying URI construction,
/// query parameter handling, and support for both absolute and relative URIs.
/// </summary>
public class UriBuilderTests
{
    /// <summary>
    /// Verifies that constructing with an absolute Uri creates a valid builder.
    /// </summary>
    [Fact]
    public void Constructor_WithAbsoluteUri_CreatesValidBuilder()
    {
        var absoluteUri = new Uri("https://example.com/path");
        var builder = new UriBuilder(absoluteUri);

        Assert.NotNull(builder);
        Assert.True(builder.Uri.IsAbsoluteUri);
        Assert.Equal("https://example.com/path", builder.Uri.ToString());
    }

    /// <summary>
    /// Verifies that constructing with a relative Uri creates a valid builder.
    /// </summary>
    [Fact]
    public void Constructor_WithRelativeUri_CreatesValidBuilder()
    {
        var relativeUri = new Uri("/auth", UriKind.Relative);
        var builder = new UriBuilder(relativeUri);

        Assert.NotNull(builder);
        Assert.False(builder.Uri.IsAbsoluteUri);
        Assert.Equal("/auth", builder.Uri.ToString());
    }

    /// <summary>
    /// Verifies that query parameters are correctly appended to absolute URIs.
    /// </summary>
    [Fact]
    public void AbsoluteUri_WithQueryParameters_BuildsCorrectly()
    {
        var absoluteUri = new Uri("https://example.com/path");
        var builder = new UriBuilder(absoluteUri)
        {
            Query =
            {
                ["param1"] = "value1",
                ["param2"] = "value2"
            }
        };

        var result = builder.Uri;
        Assert.True(result.IsAbsoluteUri);
        Assert.Contains("param1=value1", result.ToString());
        Assert.Contains("param2=value2", result.ToString());
    }

    /// <summary>
    /// Verifies that query parameters are correctly appended to relative URIs with proper URL encoding.
    /// </summary>
    [Fact]
    public void RelativeUri_WithQueryParameters_BuildsCorrectly()
    {
        var relativeUri = new Uri("/auth", UriKind.Relative);
        var builder = new UriBuilder(relativeUri)
        {
            Query =
            {
                ["email"] = "user@example.com",
                ["remaining_steps"] = "terms_acceptance"
            }
        };

        var result = builder.Uri;
        Assert.False(result.IsAbsoluteUri);
        Assert.Contains("email=user%40example.com", result.ToString());
        Assert.Contains("remaining_steps=terms_acceptance", result.ToString());
        Assert.StartsWith("/auth?", result.ToString());
    }

    /// <summary>
    /// Verifies that multiple query parameters preserve the original path structure.
    /// </summary>
    [Fact]
    public void RelativeUri_WithMultipleParameters_PreservesPath()
    {
        var relativeUri = new Uri("/auth/callback", UriKind.Relative);
        var builder = new UriBuilder(relativeUri)
        {
            Query =
            {
                ["code"] = "abc123",
                ["state"] = "xyz789"
            }
        };

        var result = builder.Uri;
        Assert.False(result.IsAbsoluteUri);
        Assert.StartsWith("/auth/callback?", result.ToString());
    }

    /// <summary>
    /// Verifies that fragments are correctly appended to relative URIs along with query parameters.
    /// </summary>
    [Fact]
    public void RelativeUri_WithFragment_BuildsCorrectly()
    {
        var relativeUri = new Uri("/page", UriKind.Relative);
        var builder = new UriBuilder(relativeUri)
        {
            Query = { ["param"] = "value" },
            Fragment = { ["section"] = "top" }
        };

        var result = builder.Uri;
        Assert.False(result.IsAbsoluteUri);
        Assert.Contains("param=value", result.ToString());
        Assert.Contains("#section=top", result.ToString());
    }

    /// <summary>
    /// Verifies that fragments are correctly appended to absolute URIs along with query parameters.
    /// </summary>
    [Fact]
    public void AbsoluteUri_WithFragment_BuildsCorrectly()
    {
        var absoluteUri = new Uri("https://example.com/page");
        var builder = new UriBuilder(absoluteUri)
        {
            Query = { ["param"] = "value" },
            Fragment = { ["section"] = "top" }
        };

        var result = builder.Uri;
        Assert.True(result.IsAbsoluteUri);
        Assert.Contains("param=value", result.ToString());
        Assert.Contains("#section=top", result.ToString());
    }

    /// <summary>
    /// Verifies implicit conversion from UriBuilder to Uri works correctly.
    /// </summary>
    [Fact]
    public void ImplicitConversionToUri_WorksForRelativeUri()
    {
        var relativeUri = new Uri("/auth", UriKind.Relative);
        var builder = new UriBuilder(relativeUri);

        Uri result = builder;

        Assert.False(result.IsAbsoluteUri);
        Assert.Equal("/auth", result.ToString());
    }

    /// <summary>
    /// Verifies implicit conversion from UriBuilder to string works correctly.
    /// </summary>
    [Fact]
    public void ImplicitConversionToString_WorksForRelativeUri()
    {
        var relativeUri = new Uri("/auth", UriKind.Relative);
        var builder = new UriBuilder(relativeUri);

        string result = builder;

        Assert.Equal("/auth", result);
    }

    /// <summary>
    /// Verifies that string constructor correctly handles various relative path formats.
    /// </summary>
    [Theory]
    [InlineData("/path")]
    [InlineData("/path/subpath")]
    [InlineData("/path/relative")]
    [InlineData("/auth/api/signin-oidc")]
    public void Constructor_WithRelativePathString_CreatesRelativeUri(string relativePath)
    {
        var builder = new UriBuilder(relativePath);

        var result = builder.Uri;
        Assert.False(result.IsAbsoluteUri);
        Assert.Equal(relativePath, result.ToString());
    }

    /// <summary>
    /// Verifies that string constructor correctly handles various absolute URI formats.
    /// Note: URIs without paths automatically add a trailing slash.
    /// </summary>
    [Theory]
    [InlineData("https://example.com", "https://example.com/")]
    [InlineData("https://example.com/path", "https://example.com/path")]
    [InlineData("http://localhost:5000/auth", "http://localhost:5000/auth")]
    public void Constructor_WithAbsoluteUriString_CreatesAbsoluteUri(string absoluteUri, string expected)
    {
        var builder = new UriBuilder(absoluteUri);

        var result = builder.Uri;
        Assert.True(result.IsAbsoluteUri);
        Assert.Equal(expected, result.ToString());
    }

    /// <summary>
    /// Verifies that relative path strings with query parameters build correctly.
    /// </summary>
    [Fact]
    public void Constructor_WithRelativePathString_WithQueryParameters()
    {
        var builder = new UriBuilder("/auth/callback")
        {
            Query =
            {
                ["code"] = "abc123",
                ["state"] = "xyz789"
            }
        };

        var result = builder.Uri;
        Assert.False(result.IsAbsoluteUri);
        Assert.StartsWith("/auth/callback?", result.ToString());
        Assert.Contains("code=abc123", result.ToString());
        Assert.Contains("state=xyz789", result.ToString());
    }

    /// <summary>
    /// Verifies that PathString.Value works correctly with UriBuilder.
    /// PathString is commonly used in ASP.NET Core configuration (e.g., ExternalProvidersSettings.LinkedAccountsPath).
    /// </summary>
    [Fact]
    public void Constructor_WithPathStringValue_CreatesRelativeUri()
    {
        var pathString = new PathString("/manage/linked_accounts");

        var builder = new UriBuilder(pathString.Value);

        var result = builder.Uri;
        Assert.False(result.IsAbsoluteUri);
        Assert.Equal("/manage/linked_accounts", result.ToString());
    }

    /// <summary>
    /// Verifies that PathString with query parameters works correctly.
    /// This mirrors the production scenario in ExternalAdminResponseHandler.
    /// </summary>
    [Fact]
    public void Constructor_WithPathStringValue_WithQueryParameters()
    {
        var pathString = new PathString("/manage/linked_accounts");

        var builder = new UriBuilder(pathString.Value)
        {
            Query =
            {
                ["provider"] = "google",
                ["error"] = "ACCOUNT_ALREADY_EXISTS"
            }
        };

        var result = builder.Uri;
        Assert.False(result.IsAbsoluteUri);
        Assert.Contains("/manage/linked_accounts?", result.ToString());
        Assert.Contains("provider=google", result.ToString());
        Assert.Contains("error=ACCOUNT_ALREADY_EXISTS", result.ToString());
    }

    /// <summary>
    /// Verifies that PathString.ToString() works identically to PathString.Value.
    /// </summary>
    [Fact]
    public void Constructor_WithPathStringToString_CreatesRelativeUri()
    {
        var pathString = new PathString("/auth/api/signin-oidc");

        var builder = new UriBuilder(pathString.ToString());

        var result = builder.Uri;
        Assert.False(result.IsAbsoluteUri);
        Assert.Equal("/auth/api/signin-oidc", result.ToString());
    }

    /// <summary>
    /// Verifies that default HTTPS port (443) is omitted from the URI.
    /// </summary>
    [Fact]
    public void AbsoluteUri_WithDefaultHttpsPort_OmitsPort()
    {
        var absoluteUri = new Uri("https://example.com/path");
        var builder = new UriBuilder(absoluteUri)
        {
            Query = { ["param"] = "value" }
        };

        var result = builder.Uri;
        Assert.True(result.IsAbsoluteUri);
        Assert.Equal("https://example.com/path?param=value", result.ToString());
        Assert.DoesNotContain(":443", result.ToString());
    }

    /// <summary>
    /// Verifies that default HTTP port (80) is omitted from the URI.
    /// </summary>
    [Fact]
    public void AbsoluteUri_WithDefaultHttpPort_OmitsPort()
    {
        var absoluteUri = new Uri("http://example.com/path");
        var builder = new UriBuilder(absoluteUri);

        var result = builder.Uri;
        Assert.True(result.IsAbsoluteUri);
        Assert.Equal("http://example.com/path", result.ToString());
        Assert.DoesNotContain(":80", result.ToString());
    }

    /// <summary>
    /// Verifies that non-default ports are included in the URI.
    /// </summary>
    [Fact]
    public void AbsoluteUri_WithNonDefaultPort_IncludesPort()
    {
        var absoluteUri = new Uri("https://localhost:5001/api");
        var builder = new UriBuilder(absoluteUri)
        {
            Query = { ["param"] = "value" }
        };

        var result = builder.Uri;
        Assert.True(result.IsAbsoluteUri);
        Assert.Contains(":5001", result.ToString());
        Assert.Equal("https://localhost:5001/api?param=value", result.ToString());
    }

    /// <summary>
    /// Verifies that default FTP port (21) is omitted from the URI.
    /// </summary>
    [Fact]
    public void AbsoluteUri_WithDefaultFtpPort_OmitsPort()
    {
        var absoluteUri = new Uri("ftp://ftp.example.com/files");
        var builder = new UriBuilder(absoluteUri);

        var result = builder.Uri;
        Assert.True(result.IsAbsoluteUri);
        Assert.Equal("ftp://ftp.example.com/files", result.ToString());
        Assert.DoesNotContain(":21", result.ToString());
    }

    /// <summary>
    /// Verifies that non-standard schemes with ports keep the port in the URI.
    /// </summary>
    [Fact]
    public void AbsoluteUri_WithNonStandardScheme_KeepsPort()
    {
        var absoluteUri = new Uri("ws://localhost:8080/socket");
        var builder = new UriBuilder(absoluteUri);

        var result = builder.Uri;
        Assert.True(result.IsAbsoluteUri);
        Assert.Contains(":8080", result.ToString());
    }

    /// <summary>
    /// Verifies that relative URIs without leading slash are correctly handled.
    /// This is the Telegram webhook case: "setWebhook" should become a valid path.
    /// </summary>
    [Fact]
    public void Constructor_WithRelativePathWithoutLeadingSlash_CreatesValidUri()
    {
        var builder = new UriBuilder("setWebhook");

        var result = builder.Uri;
        Assert.False(result.IsAbsoluteUri);
        Assert.Equal("setWebhook", result.ToString());
    }

    /// <summary>
    /// Verifies that relative URIs without leading slash work correctly with query parameters.
    /// This reproduces the Telegram webhook registration issue where
    /// new UriBuilder("setWebhook") { Query = { ["url"] = "..." } } should work.
    /// </summary>
    [Fact]
    public void RelativeUri_WithoutLeadingSlash_WithQueryParameters_BuildsCorrectly()
    {
        var builder = new UriBuilder("setWebhook")
        {
            Query = { ["url"] = "https://example.com/webhook" }
        };

        var result = builder.Uri;
        Assert.False(result.IsAbsoluteUri);
        Assert.StartsWith("setWebhook?", result.ToString());
        Assert.Contains("url=https%3a%2f%2fexample.com%2fwebhook", result.ToString());
    }

    /// <summary>
    /// Verifies that relative URIs without leading slash can be combined with HttpClient BaseAddress.
    /// When HttpClient has BaseAddress="https://api.telegram.org/bot123/" and we POST to "setWebhook?url=...",
    /// the resulting URL should be "https://api.telegram.org/bot123/setWebhook?url=..."
    /// </summary>
    [Fact]
    public void RelativeUri_WithoutLeadingSlash_CanBeCombinedWithBaseAddress()
    {
        var baseAddress = new Uri("https://api.telegram.org/bot123/");
        var relativeUri = new UriBuilder("setWebhook")
        {
            Query = { ["url"] = "https://example.com/webhook" }
        }.Uri;

        var combined = new Uri(baseAddress, relativeUri);

        Assert.True(combined.IsAbsoluteUri);
        Assert.Equal("https://api.telegram.org/bot123/setWebhook?url=https%3a%2f%2fexample.com%2fwebhook", combined.ToString());
    }
}
