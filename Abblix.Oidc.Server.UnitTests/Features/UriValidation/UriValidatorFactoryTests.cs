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
/// Unit tests for <see cref="UriValidatorFactory"/> verifying factory pattern for creating URI validators.
/// Tests the creation of appropriate validator types (ExactMatch vs Composite)
/// based on the number of registered URIs and configuration options.
/// </summary>
public class UriValidatorFactoryTests
{
    /// <summary>
    /// Verifies that creating a validator with a single URI returns an ExactMatchUriValidator.
    /// Optimization: uses simpler validator type when only one URI is registered.
    /// </summary>
    [Fact]
    public void Create_WithSingleUri_ReturnsExactMatchValidator()
    {
        var uri = new Uri(TestConstants.DefaultRedirectUri);

        var validator = UriValidatorFactory.Create(uri);

        Assert.IsType<ExactMatchUriValidator>(validator);
        Assert.True(validator.IsValid(uri));
    }

    /// <summary>
    /// Verifies that creating a validator with multiple URIs returns a CompositeUriValidator.
    /// Composite pattern allows validation against any of the registered URIs.
    /// </summary>
    [Fact]
    public void Create_WithMultipleUris_ReturnsCompositeValidator()
    {
        var uri1 = new Uri("https://example.com/callback1");
        var uri2 = new Uri("https://example.com/callback2");

        var validator = UriValidatorFactory.Create(uri1, uri2);

        Assert.IsType<CompositeUriValidator>(validator);
        Assert.True(validator.IsValid(uri1));
        Assert.True(validator.IsValid(uri2));
    }

    /// <summary>
    /// Verifies that the ignoreQueryAndFragment parameter is properly passed to created validators.
    /// When enabled, query strings and fragments are ignored during validation.
    /// </summary>
    [Fact]
    public void Create_WithIgnoreQueryAndFragment_ValidatorIgnoresQueryAndFragment()
    {
        var baseUri = new Uri(TestConstants.DefaultRedirectUri);
        var uriWithQuery = new Uri("https://example.com/callback?param=value");

        var validator = UriValidatorFactory.Create(ignoreQueryAndFragment: true, baseUri);

        Assert.True(validator.IsValid(baseUri));
        Assert.True(validator.IsValid(uriWithQuery));
    }

    /// <summary>
    /// Verifies that query strings and fragments are validated by default (strict mode).
    /// Critical for security - prevents malicious query parameters on redirect URIs.
    /// </summary>
    [Fact]
    public void Create_WithoutIgnoreQueryAndFragment_ValidatorDoesNotIgnore()
    {
        var baseUri = new Uri(TestConstants.DefaultRedirectUri);
        var uriWithQuery = new Uri("https://example.com/callback?param=value");

        var validator = UriValidatorFactory.Create(ignoreQueryAndFragment: false, baseUri);

        Assert.True(validator.IsValid(baseUri));
        Assert.False(validator.IsValid(uriWithQuery));
    }

    /// <summary>
    /// Verifies that validators created with multiple URIs validate all registered URIs correctly.
    /// Tests that all URIs are properly registered and unregistered URIs are rejected.
    /// </summary>
    [Fact]
    public void Create_WithThreeUris_ValidatesAllThree()
    {
        var uri1 = new Uri("https://example.com/callback1");
        var uri2 = new Uri("https://example.com/callback2");
        var uri3 = new Uri("https://example.com/callback3");

        var validator = UriValidatorFactory.Create(uri1, uri2, uri3);

        Assert.True(validator.IsValid(uri1));
        Assert.True(validator.IsValid(uri2));
        Assert.True(validator.IsValid(uri3));
        Assert.False(validator.IsValid(new Uri("https://example.com/callback4")));
    }

    /// <summary>
    /// Verifies that ignoreQueryAndFragment applies to all registered URIs in a composite validator.
    /// Consistent configuration across all URIs in the validator chain.
    /// </summary>
    [Fact]
    public void Create_MultipleUrisWithIgnoreQueryAndFragment_AllIgnoreQueryAndFragment()
    {
        var uri1 = new Uri("https://example.com/callback1");
        var uri2 = new Uri("https://example.com/callback2");

        var validator = UriValidatorFactory.Create(ignoreQueryAndFragment: true, uri1, uri2);

        Assert.True(validator.IsValid(new Uri("https://example.com/callback1?query=1")));
        Assert.True(validator.IsValid(new Uri("https://example.com/callback2#fragment")));
    }

    /// <summary>
    /// Verifies that validators can be created for multiple domains.
    /// Supports multi-domain applications (e.g., *.example.com subdomains).
    /// Security critical: ensures malicious domains are still rejected.
    /// </summary>
    [Fact]
    public void Create_WithDifferentDomains_ValidatesCorrectly()
    {
        var uri1 = new Uri("https://app1.example.com/callback");
        var uri2 = new Uri("https://app2.example.com/callback");
        var uri3 = new Uri("https://app3.example.com/callback");

        var validator = UriValidatorFactory.Create(uri1, uri2, uri3);

        Assert.True(validator.IsValid(uri1));
        Assert.True(validator.IsValid(uri2));
        Assert.True(validator.IsValid(uri3));
        Assert.False(validator.IsValid(new Uri("https://malicious.com/callback")));
    }

    /// <summary>
    /// Verifies that localhost (development) and production URIs can be registered together.
    /// Common scenario for applications supporting both local development and deployed environments.
    /// </summary>
    [Fact]
    public void Create_WithLocalhostAndProduction_ValidatesBoth()
    {
        var localhost = new Uri("http://localhost:3000/callback");
        var production = new Uri(TestConstants.DefaultRedirectUri);

        var validator = UriValidatorFactory.Create(localhost, production);

        Assert.True(validator.IsValid(localhost));
        Assert.True(validator.IsValid(production));
    }
}
