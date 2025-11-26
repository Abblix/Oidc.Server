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
using Abblix.Oidc.Server.Features.UriValidation;
using Abblix.Oidc.Server.UnitTests.TestInfrastructure;
using Xunit;

namespace Abblix.Oidc.Server.UnitTests.Features.UriValidation;

/// <summary>
/// Unit tests for <see cref="ExactMatchUriValidator"/> verifying exact URI matching for OAuth/OIDC redirect URIs.
/// Tests cover security-critical validation scenarios to prevent open redirect vulnerabilities
/// by ensuring strict URI matching with configurable handling of query strings and fragments.
/// </summary>
public class ExactMatchUriValidatorTests
{
    /// <summary>
    /// Verifies that an exact match of the valid URI returns true.
    /// This is the basic positive test case for redirect URI validation.
    /// </summary>
    [Fact]
    public void ExactMatch_ValidUri_ReturnsTrue()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new ExactMatchUriValidator(validUri);

        var result = validator.IsValid(validUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that a different URI path returns false.
    /// Critical for preventing redirect attacks to unauthorized endpoints.
    /// </summary>
    [Fact]
    public void ExactMatch_DifferentUri_ReturnsFalse()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new ExactMatchUriValidator(validUri);

        var testUri = new Uri("https://example.com/different");
        var result = validator.IsValid(testUri);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that URIs with query strings are rejected by default.
    /// Prevents attackers from appending malicious query parameters to valid redirect URIs.
    /// </summary>
    [Fact]
    public void ExactMatch_WithQueryString_Default_ReturnsFalse()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new ExactMatchUriValidator(validUri);

        var testUri = new Uri("https://example.com/callback?param=value");
        var result = validator.IsValid(testUri);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that URI fragments are ignored by default (per OAuth 2.0 spec).
    /// Fragments are never sent to the server, so they don't affect security.
    /// </summary>
    [Fact]
    public void ExactMatch_WithFragment_Default_ReturnsTrue()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new ExactMatchUriValidator(validUri);

        var testUri = new Uri("https://example.com/callback#fragment");
        var result = validator.IsValid(testUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that query strings are allowed when explicitly configured to ignore them.
    /// Useful for scenarios where dynamic query parameters are expected.
    /// </summary>
    [Fact]
    public void ExactMatch_WithQueryString_IgnoreEnabled_ReturnsTrue()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new ExactMatchUriValidator(validUri, ignoreQueryAndFragment: true);

        var testUri = new Uri("https://example.com/callback?param=value");
        var result = validator.IsValid(testUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that fragments continue to be ignored when fragment ignoring is explicitly enabled.
    /// Demonstrates consistent fragment handling across configurations.
    /// </summary>
    [Fact]
    public void ExactMatch_WithFragment_IgnoreEnabled_ReturnsTrue()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new ExactMatchUriValidator(validUri, ignoreQueryAndFragment: true);

        var testUri = new Uri("https://example.com/callback#fragment");
        var result = validator.IsValid(testUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that both query strings and fragments are correctly handled when ignoring is enabled.
    /// Tests combined query and fragment scenarios.
    /// </summary>
    [Fact]
    public void ExactMatch_WithQueryAndFragment_IgnoreEnabled_ReturnsTrue()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new ExactMatchUriValidator(validUri, ignoreQueryAndFragment: true);

        var testUri = new Uri("https://example.com/callback?param=value#fragment");
        var result = validator.IsValid(testUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that different URI schemes (http vs https) are rejected.
    /// Critical security check - prevents downgrade attacks from HTTPS to HTTP.
    /// </summary>
    [Fact]
    public void ExactMatch_DifferentScheme_ReturnsFalse()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new ExactMatchUriValidator(validUri);

        var testUri = new Uri("http://example.com/callback");
        var result = validator.IsValid(testUri);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that different hostnames are rejected.
    /// Essential for preventing cross-domain redirect attacks.
    /// </summary>
    [Fact]
    public void ExactMatch_DifferentHost_ReturnsFalse()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new ExactMatchUriValidator(validUri);

        var testUri = new Uri("https://different.com/callback");
        var result = validator.IsValid(testUri);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that different ports are rejected.
    /// Prevents redirects to malicious services on different ports of the same host.
    /// </summary>
    [Fact]
    public void ExactMatch_DifferentPort_ReturnsFalse()
    {
        var validUri = new Uri("https://example.com:443/callback");
        var validator = new ExactMatchUriValidator(validUri);

        var testUri = new Uri("https://example.com:8443/callback");
        var result = validator.IsValid(testUri);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that different paths are rejected.
    /// Core security feature preventing unauthorized endpoint access.
    /// </summary>
    [Fact]
    public void ExactMatch_DifferentPath_ReturnsFalse()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new ExactMatchUriValidator(validUri);

        var testUri = new Uri("https://example.com/callback/sub");
        var result = validator.IsValid(testUri);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that path matching is case-sensitive.
    /// Ensures strict path validation per URI RFC specifications.
    /// </summary>
    [Fact]
    public void ExactMatch_CaseSensitivePath_ReturnsFalse()
    {
        var validUri = new Uri("https://example.com/Callback");
        var validator = new ExactMatchUriValidator(validUri);

        var testUri = new Uri("https://example.com/callback");
        var result = validator.IsValid(testUri);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that trailing slashes matter in path comparison.
    /// "/path" and "/path/" are treated as different URIs per RFC standards.
    /// </summary>
    [Fact]
    public void ExactMatch_WithTrailingSlash_Different_ReturnsFalse()
    {
        var validUri = new Uri("https://example.com/callback/");
        var validator = new ExactMatchUriValidator(validUri);

        var testUri = new Uri("https://example.com/callback");
        var result = validator.IsValid(testUri);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that passing null to the constructor throws ArgumentException.
    /// Ensures proper input validation and prevents null reference errors.
    /// </summary>
    [Fact]
    public void Constructor_WithNullUri_ThrowsArgumentException()
    {
        Assert.Throws<ArgumentException>(() => new ExactMatchUriValidator(null!));
    }

    /// <summary>
    /// Verifies that relative URIs are rejected in the constructor.
    /// Only absolute URIs are valid for OAuth/OIDC redirect URI validation.
    /// </summary>
    [Fact]
    public void Constructor_WithRelativeUri_ThrowsArgumentException()
    {
        var relativeUri = new Uri("/callback", UriKind.Relative);

        Assert.Throws<ArgumentException>(() => new ExactMatchUriValidator(relativeUri));
    }

    /// <summary>
    /// Verifies that complex query strings with multiple parameters are handled correctly
    /// when query ignoring is enabled. Tests edge cases with special characters.
    /// </summary>
    [Fact]
    public void ExactMatch_WithComplexQueryString_IgnoreEnabled_ReturnsTrue()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new ExactMatchUriValidator(validUri, ignoreQueryAndFragment: true);

        var testUri = new Uri("https://example.com/callback?param1=value1&param2=value2&param3=value%20with%20spaces");
        var result = validator.IsValid(testUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that IP address-based URIs are validated correctly.
    /// Important for localhost development and internal network scenarios.
    /// </summary>
    [Fact]
    public void ExactMatch_WithIPAddress_ValidatesCorrectly()
    {
        var validUri = new Uri("https://192.168.1.1/callback");
        var validator = new ExactMatchUriValidator(validUri);

        var result = validator.IsValid(validUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that localhost URIs are validated correctly.
    /// Common scenario for development and testing environments.
    /// </summary>
    [Fact]
    public void ExactMatch_WithLocalhost_ValidatesCorrectly()
    {
        var validUri = new Uri("http://localhost:8080/callback");
        var validator = new ExactMatchUriValidator(validUri);

        var result = validator.IsValid(validUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that custom URI schemes (e.g., myapp://) are validated correctly.
    /// Supports mobile app deep linking and custom protocol handlers.
    /// </summary>
    [Fact]
    public void ExactMatch_WithCustomScheme_ValidatesCorrectly()
    {
        var validUri = new Uri("custom-scheme://example.com/callback");
        var validator = new ExactMatchUriValidator(validUri);

        var result = validator.IsValid(validUri);

        Assert.True(result);
    }
}
