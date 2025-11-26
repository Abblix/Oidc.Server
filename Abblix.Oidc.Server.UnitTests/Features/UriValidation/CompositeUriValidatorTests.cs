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
/// Unit tests for <see cref="CompositeUriValidator"/> verifying composite pattern for URI validation.
/// Tests the ability to validate URIs against multiple registered redirect URIs,
/// supporting scenarios where clients have multiple valid callback endpoints.
/// </summary>
public class CompositeUriValidatorTests
{
    /// <summary>
    /// Verifies that a composite validator with a single validator works correctly for matching URIs.
    /// Basic test ensuring the composite pattern doesn't break single validator functionality.
    /// </summary>
    [Fact]
    public void Composite_WithSingleValidator_MatchingUri_ReturnsTrue()
    {
        var validUri = new Uri(TestConstants.DefaultRedirectUri);
        var validator = new CompositeUriValidator(new ExactMatchUriValidator(validUri));

        var result = validator.IsValid(validUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that matching the first registered URI returns true.
    /// Tests early-exit optimization where validation stops after first match.
    /// </summary>
    [Fact]
    public void Composite_WithMultipleValidators_MatchingFirstUri_ReturnsTrue()
    {
        var validator = new CompositeUriValidator(
            new ExactMatchUriValidator(new Uri("https://example.com/callback1")),
            new ExactMatchUriValidator(new Uri("https://example.com/callback2"))
        );

        var testUri = new Uri("https://example.com/callback1");
        var result = validator.IsValid(testUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that matching a non-first registered URI returns true.
    /// Ensures all validators in the chain are checked until a match is found.
    /// </summary>
    [Fact]
    public void Composite_WithMultipleValidators_MatchingSecondUri_ReturnsTrue()
    {
        var validator = new CompositeUriValidator(
            new ExactMatchUriValidator(new Uri("https://example.com/callback1")),
            new ExactMatchUriValidator(new Uri("https://example.com/callback2"))
        );

        var testUri = new Uri("https://example.com/callback2");
        var result = validator.IsValid(testUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that when no registered URI matches, validation returns false.
    /// Critical security check ensuring unregistered URIs are rejected.
    /// </summary>
    [Fact]
    public void Composite_WithMultipleValidators_NoMatch_ReturnsFalse()
    {
        var validator = new CompositeUriValidator(
            new ExactMatchUriValidator(new Uri("https://example.com/callback1")),
            new ExactMatchUriValidator(new Uri("https://example.com/callback2"))
        );

        var testUri = new Uri("https://example.com/callback3");
        var result = validator.IsValid(testUri);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that composite validators scale correctly with many registered URIs.
    /// Tests scenarios where clients have multiple callback endpoints (e.g., multi-tenant apps).
    /// </summary>
    [Fact]
    public void Composite_WithManyValidators_MatchingAny_ReturnsTrue()
    {
        var validator = new CompositeUriValidator(
            new ExactMatchUriValidator(new Uri("https://example.com/callback1")),
            new ExactMatchUriValidator(new Uri("https://example.com/callback2")),
            new ExactMatchUriValidator(new Uri("https://example.com/callback3")),
            new ExactMatchUriValidator(new Uri("https://example.com/callback4")),
            new ExactMatchUriValidator(new Uri("https://example.com/callback5"))
        );

        var testUri = new Uri("https://example.com/callback3");
        var result = validator.IsValid(testUri);

        Assert.True(result);
    }

    /// <summary>
    /// Verifies that validators can handle multiple hosts/domains.
    /// Supports scenarios like multi-domain applications or separate dev/staging/production endpoints.
    /// </summary>
    [Fact]
    public void Composite_WithDifferentHosts_MatchesCorrectly()
    {
        var validator = new CompositeUriValidator(
            new ExactMatchUriValidator(new Uri("https://app1.example.com/callback")),
            new ExactMatchUriValidator(new Uri("https://app2.example.com/callback")),
            new ExactMatchUriValidator(new Uri("https://app3.example.com/callback"))
        );

        Assert.True(validator.IsValid(new Uri("https://app1.example.com/callback")));
        Assert.True(validator.IsValid(new Uri("https://app2.example.com/callback")));
        Assert.True(validator.IsValid(new Uri("https://app3.example.com/callback")));
        Assert.False(validator.IsValid(new Uri("https://app4.example.com/callback")));
    }

    /// <summary>
    /// Verifies that validators can handle multiple URI schemes (https, http, custom).
    /// Supports web apps, local development, and mobile app deep linking scenarios.
    /// </summary>
    [Fact]
    public void Composite_WithDifferentSchemes_MatchesCorrectly()
    {
        var validator = new CompositeUriValidator(
            new ExactMatchUriValidator(new Uri(TestConstants.DefaultRedirectUri)),
            new ExactMatchUriValidator(new Uri("http://example.com/callback")),
            new ExactMatchUriValidator(new Uri("custom://example.com/callback"))
        );

        Assert.True(validator.IsValid(new Uri(TestConstants.DefaultRedirectUri)));
        Assert.True(validator.IsValid(new Uri("http://example.com/callback")));
        Assert.True(validator.IsValid(new Uri("custom://example.com/callback")));
        Assert.False(validator.IsValid(new Uri("ftp://example.com/callback")));
    }

    /// <summary>
    /// Verifies that validators with different query/fragment handling configurations work together.
    /// Tests complex scenarios where some URIs accept query parameters and others don't.
    /// </summary>
    [Fact]
    public void Composite_WithMixedIgnoreQueryFragment_MatchesCorrectly()
    {
        var validator = new CompositeUriValidator(
            new ExactMatchUriValidator(new Uri("https://example.com/callback1"), ignoreQueryAndFragment: true),
            new ExactMatchUriValidator(new Uri("https://example.com/callback2"), ignoreQueryAndFragment: false)
        );

        Assert.True(validator.IsValid(new Uri("https://example.com/callback1?query=value")));
        Assert.True(validator.IsValid(new Uri("https://example.com/callback2")));
        Assert.False(validator.IsValid(new Uri("https://example.com/callback2?query=value")));
    }

    /// <summary>
    /// Verifies that a composite validator with no registered validators rejects all URIs.
    /// Edge case handling for empty validator lists.
    /// </summary>
    [Fact]
    public void Composite_EmptyValidatorList_ReturnsFalse()
    {
        var validator = new CompositeUriValidator(Array.Empty<IUriValidator>());

        var testUri = new Uri(TestConstants.DefaultRedirectUri);
        var result = validator.IsValid(testUri);

        Assert.False(result);
    }

    /// <summary>
    /// Verifies that localhost (development) and production URIs can coexist.
    /// Common real-world scenario supporting both local testing and deployed environments.
    /// </summary>
    [Fact]
    public void Composite_WithLocalhostAndProduction_MatchesBoth()
    {
        var validator = new CompositeUriValidator(
            new ExactMatchUriValidator(new Uri("http://localhost:3000/callback")),
            new ExactMatchUriValidator(new Uri(TestConstants.DefaultRedirectUri))
        );

        Assert.True(validator.IsValid(new Uri("http://localhost:3000/callback")));
        Assert.True(validator.IsValid(new Uri(TestConstants.DefaultRedirectUri)));
        Assert.False(validator.IsValid(new Uri("http://localhost:3001/callback")));
    }
}
