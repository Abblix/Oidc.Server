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

using System;
using System.Collections.Generic;
using Abblix.Oidc.Server.Features.LogoutNotification;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.LogoutNotification;

/// <summary>
/// Unit tests for <see cref="FrontChannelLogoutService"/> verifying HTML generation
/// for front-channel logout pages per OpenID Connect Front-Channel Logout 1.0 specification.
/// </summary>
public class FrontChannelLogoutServiceTests
{
    private const string PostLogoutUri = "https://client.example.com/post-logout";
    private const string LogoutUri1 = "https://app1.example.com/logout";
    private const string LogoutUri2 = "https://app2.example.com/logout";

    private readonly FrontChannelLogoutService _service = new();

    /// <summary>
    /// Verifies that HTML content contains iframe elements for each logout URI.
    /// </summary>
    [Fact]
    public void GetFrontChannelLogoutResponse_ContainsIframesForAllUris()
    {
        // Arrange
        var uris = CreateLogoutUris();

        // Act
        var response = _service.GetFrontChannelLogoutResponse(new Uri(PostLogoutUri), uris);

        // Assert
        Assert.Contains($"<iframe src=\"{LogoutUri1}\">", response.HtmlContent);
        Assert.Contains($"<iframe src=\"{LogoutUri2}\">", response.HtmlContent);
    }

    /// <summary>
    /// Verifies that postLogoutUri is null in script when not provided.
    /// </summary>
    [Fact]
    public void GetFrontChannelLogoutResponse_WithoutPostLogoutUri_ScriptContainsNull()
    {
        // Arrange
        var uris = CreateLogoutUris();

        // Act
        var response = _service.GetFrontChannelLogoutResponse(null, uris);

        // Assert
        Assert.Contains("<script", response.HtmlContent);
        Assert.Contains("var postLogoutUri = null;", response.HtmlContent);
    }

    /// <summary>
    /// Verifies that postLogoutRedirectUri is included in the HTML content.
    /// </summary>
    [Fact]
    public void GetFrontChannelLogoutResponse_IncludesPostLogoutUri()
    {
        // Arrange
        var uris = CreateLogoutUris();

        // Act
        var response = _service.GetFrontChannelLogoutResponse(new Uri(PostLogoutUri), uris);

        // Assert
        Assert.Contains(PostLogoutUri, response.HtmlContent);
    }

    /// <summary>
    /// Verifies that logout URIs with special characters are HTML-encoded.
    /// </summary>
    [Fact]
    public void GetFrontChannelLogoutResponse_EncodesLogoutUrisForHtml()
    {
        // Arrange
        var uris = new List<Uri> { new("https://app.example.com/logout?a=1&b=2") };

        // Act
        var response = _service.GetFrontChannelLogoutResponse(new Uri(PostLogoutUri), uris);

        // Assert
        Assert.Contains("&amp;", response.HtmlContent);
        Assert.DoesNotContain("?a=1&b=2\"", response.HtmlContent);
    }

    /// <summary>
    /// Verifies that postLogoutRedirectUri with special characters is JavaScript-encoded.
    /// </summary>
    [Fact]
    public void GetFrontChannelLogoutResponse_EncodesPostLogoutUriForJavaScript()
    {
        // Arrange
        var uris = CreateLogoutUris();
        var postLogoutUri = new Uri("https://client.example.com/callback?state=abc\"def");

        // Act
        var response = _service.GetFrontChannelLogoutResponse(postLogoutUri, uris);

        // Assert
        Assert.Contains("\\\"", response.HtmlContent);
        Assert.DoesNotContain("abc\"def", response.HtmlContent);
    }

    /// <summary>
    /// Verifies that FrameSources contains all unique origins.
    /// </summary>
    [Fact]
    public void GetFrontChannelLogoutResponse_FrameSourcesContainsAllOrigins()
    {
        // Arrange
        var uris = CreateLogoutUris();

        // Act
        var response = _service.GetFrontChannelLogoutResponse(new Uri(PostLogoutUri), uris);

        // Assert
        Assert.Contains("https://app1.example.com", response.FrameSources);
        Assert.Contains("https://app2.example.com", response.FrameSources);
    }

    /// <summary>
    /// Verifies that duplicate origins are deduplicated in FrameSources.
    /// </summary>
    [Fact]
    public void GetFrontChannelLogoutResponse_DeduplicatesOrigins()
    {
        // Arrange
        var uris = new List<Uri>
        {
            new("https://app.example.com/logout1"),
            new("https://app.example.com/logout2"),
            new("https://other.example.com/logout"),
        };

        // Act
        var response = _service.GetFrontChannelLogoutResponse(new Uri(PostLogoutUri), uris);

        // Assert
        Assert.Equal(2, response.FrameSources.Count);
        Assert.Contains("https://app.example.com", response.FrameSources);
        Assert.Contains("https://other.example.com", response.FrameSources);
    }

    /// <summary>
    /// Verifies that Nonce is generated with valid Base64 format.
    /// </summary>
    [Fact]
    public void GetFrontChannelLogoutResponse_GeneratesValidBase64Nonce()
    {
        // Arrange
        var uris = CreateLogoutUris();

        // Act
        var response = _service.GetFrontChannelLogoutResponse(new Uri(PostLogoutUri), uris);

        // Assert
        Assert.NotEmpty(response.Nonce);
        Assert.True(IsValidBase64(response.Nonce), "Nonce should be valid Base64");
    }

    /// <summary>
    /// Verifies that each call generates a unique nonce.
    /// </summary>
    [Fact]
    public void GetFrontChannelLogoutResponse_GeneratesUniqueNoncePerCall()
    {
        // Arrange
        var uris = CreateLogoutUris();

        // Act
        var response1 = _service.GetFrontChannelLogoutResponse(new Uri(PostLogoutUri), uris);
        var response2 = _service.GetFrontChannelLogoutResponse(new Uri(PostLogoutUri), uris);

        // Assert
        Assert.NotEqual(response1.Nonce, response2.Nonce);
    }

    /// <summary>
    /// Verifies that HTML content contains the generated nonce in script and style tags.
    /// </summary>
    [Fact]
    public void GetFrontChannelLogoutResponse_HtmlContainsNonceInTags()
    {
        // Arrange
        var uris = CreateLogoutUris();

        // Act
        var response = _service.GetFrontChannelLogoutResponse(new Uri(PostLogoutUri), uris);

        // Assert
        Assert.Contains($"nonce=\"{response.Nonce}\"", response.HtmlContent);
    }

    private static List<Uri> CreateLogoutUris() =>
    [
        new(LogoutUri1),
        new(LogoutUri2),
    ];

    private static bool IsValidBase64(string value)
    {
        try
        {
            Convert.FromBase64String(value);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
