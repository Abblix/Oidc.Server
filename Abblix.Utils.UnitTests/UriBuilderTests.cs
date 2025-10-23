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

namespace Abblix.Utils.UnitTests;

public class UriBuilderTests
{
    [Fact]
    public void Constructor_WithAbsoluteUri_CreatesValidBuilder()
    {
        var absoluteUri = new Uri("https://example.com/path");
        var builder = new UriBuilder(absoluteUri);

        Assert.NotNull(builder);
        Assert.True(builder.Uri.IsAbsoluteUri);
        Assert.Equal("https://example.com/path", builder.Uri.ToString());
    }

    [Fact]
    public void Constructor_WithRelativeUri_CreatesValidBuilder()
    {
        var relativeUri = new Uri("/auth", UriKind.Relative);
        var builder = new UriBuilder(relativeUri);

        Assert.NotNull(builder);
        Assert.False(builder.Uri.IsAbsoluteUri);
        Assert.Equal("/auth", builder.Uri.ToString());
    }

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

    [Fact]
    public void ImplicitConversionToUri_WorksForRelativeUri()
    {
        var relativeUri = new Uri("/auth", UriKind.Relative);
        var builder = new UriBuilder(relativeUri);

        Uri result = builder;

        Assert.False(result.IsAbsoluteUri);
        Assert.Equal("/auth", result.ToString());
    }

    [Fact]
    public void ImplicitConversionToString_WorksForRelativeUri()
    {
        var relativeUri = new Uri("/auth", UriKind.Relative);
        var builder = new UriBuilder(relativeUri);

        string result = builder;

        Assert.Equal("/auth", result);
    }
}
