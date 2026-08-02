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

using Abblix.SecurityEvents.Subjects;
using Xunit;

namespace Abblix.SecurityEvents.UnitTests;

/// <summary>
/// Pins the boundary of the comparison utilities: each folds exactly what its specification
/// settles and nothing further, because anything further is one provider's rules presented as
/// everyone's.
/// </summary>
public class CanonicalizationTests
{
    [Theory]
    // The domain is case-insensitive per RFC 1034, so folding it is always safe.
    [InlineData("user@EXAMPLE.COM", "user@example.com")]
    [InlineData("user@Example.Com", "user@example.com")]
    // The local part's case sensitivity is the provider's business (RFC 9493 Section 3.2.2.1),
    // so it must survive untouched.
    [InlineData("User@example.com", "User@example.com")]
    [InlineData("USER@EXAMPLE.COM", "USER@example.com")]
    // Dots in the local part are likewise provider-specific and must survive.
    [InlineData("u.s.e.r@EXAMPLE.com", "u.s.e.r@example.com")]
    // RFC 5322 permits a quoted local part containing "@"; the split must be on the LAST one.
    [InlineData("\"odd@name\"@EXAMPLE.com", "\"odd@name\"@example.com")]
    // No domain, nothing to fold: returned unchanged rather than guessed at.
    [InlineData("not-an-email", "not-an-email")]
    [InlineData("", "")]
    public void Email_ToComparableForm_FoldsOnlyTheDomain(string input, string expected)
    {
        Assert.Equal(expected, EmailCanonicalization.ToComparableForm(input));
    }

    [Fact]
    public void Email_ToComparableForm_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => EmailCanonicalization.ToComparableForm(null!));
    }

    [Theory]
    // The named presentation separators - spaces, hyphens, parentheses, dots - fold away.
    [InlineData("+1 (206) 555-0100", "+12065550100")]
    [InlineData("+1.206.555.0100", "+12065550100")]
    [InlineData("+12065550100", "+12065550100")]
    // Not E.164 going in, not E.164 coming out: no country code is invented.
    [InlineData("(206) 555-0100", "2065550100")]
    [InlineData("", "")]
    // Anything that is not a named separator survives - a letter, a stray "+", a non-ASCII
    // character. Deleting what the method does not understand would fold genuinely distinct
    // values into one: "+1800A" and "+1800B" must not both become "+1800".
    [InlineData("+1800A", "+1800A")]
    [InlineData("+1800B", "+1800B")]
    [InlineData("1+2065550100", "1+2065550100")]
    public void PhoneNumber_ToComparableForm_RemovesOnlyPresentation(string input, string expected)
    {
        Assert.Equal(expected, PhoneNumberCanonicalization.ToComparableForm(input));
    }

    [Fact]
    public void PhoneNumber_ToComparableForm_KeepsDistinctValuesDistinct()
    {
        // The property the docs promise, asserted as a property rather than through examples.
        Assert.NotEqual(
            PhoneNumberCanonicalization.ToComparableForm("+1800A"),
            PhoneNumberCanonicalization.ToComparableForm("+1800B"));
    }

    [Fact]
    public void PhoneNumber_ToComparableForm_RejectsNull()
    {
        Assert.Throws<ArgumentNullException>(() => PhoneNumberCanonicalization.ToComparableForm(null!));
    }
}
