// Abblix OIDC Server Library
// SPDX-FileCopyrightText: Copyright (c) Abblix LLP
// SPDX-License-Identifier: Apache-2.0
//
// Licensed under the Apache License, Version 2.0. You may obtain a copy at
// http://www.apache.org/licenses/LICENSE-2.0

namespace Abblix.Utils.UnitTests;

/// <summary>
/// The string helpers with call sites outside their own file: the two predicates the library guards optional
/// parameters with, the suffix trim, and the assertion that turns an absent value into a named failure.
/// </summary>
public class StringExtensionsTests
{
    [Theory]
    [InlineData("openid", true)]
    [InlineData(" ", true)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void HasValue_AsksOnlyWhetherThereAreCharacters(string? value, bool expected)
        => Assert.Equal(expected, value.HasValue());

    [Theory]
    [InlineData("openid", true)]
    [InlineData("   ", false)]
    [InlineData("", false)]
    [InlineData(null, false)]
    public void NotNullOrWhiteSpace_TreatsBlankAsAbsent(string? value, bool expected)
        => Assert.Equal(expected, value.NotNullOrWhiteSpace());

    /// <summary>
    /// The two predicates exist side by side and differ on exactly one input, so the choice between them at a
    /// call site is a decision rather than a coin toss: a blank string is a value to <c>HasValue</c> and an
    /// absence to <c>NotNullOrWhiteSpace</c>. Pinning the disagreement is what stops one being "simplified"
    /// into the other, which would silently accept a whitespace-only parameter at five call sites.
    /// </summary>
    [Fact]
    public void ThePredicates_DisagreeOnlyOnABlankString()
    {
        const string blank = "   ";

        Assert.True(blank.HasValue());
        Assert.False(blank.NotNullOrWhiteSpace());
    }

    [Theory]
    [InlineData("https://auth.example.com/", "/", "https://auth.example.com")]
    [InlineData("https://auth.example.com", "/", "https://auth.example.com")]
    [InlineData("token.jwt", ".jwt", "token")]
    public void TrimSuffixIfExists_RemovesTheSuffixOnlyWhenItIsThere(
        string source, string suffix, string expected)
        => Assert.Equal(expected, source.TrimSuffixIfExists(suffix));

    /// <summary>
    /// An empty suffix would otherwise match the end of every string and, with the slice this method takes,
    /// return the source unchanged only by accident. The guard makes that explicit rather than incidental.
    /// </summary>
    [Fact]
    public void TrimSuffixIfExists_WithAnEmptySuffix_ReturnsTheSourceUnchanged()
        => Assert.Equal("https://auth.example.com", "https://auth.example.com".TrimSuffixIfExists(string.Empty));

    /// <summary>
    /// Retained public API with no call site in this library. Inserting after a fragment is only meaningful
    /// when the fragment is there, and the refusal names what it could not find rather than returning the
    /// source unchanged, which would hide the mistake in whatever consumed the result.
    /// </summary>
    [Theory]
    [InlineData("https://auth.example.com/token", "/token", "?x=1", "https://auth.example.com/token?x=1")]
    [InlineData("abc", "a", "X", "aXbc")]
    public void InsertAfter_PutsTheValueRightAfterTheFragment(
        string source, string fragment, string value, string expected)
        => Assert.Equal(expected, source.InsertAfter(fragment, value));

    [Fact]
    public void InsertAfter_AFragmentThatIsNotThere_IsRefusedAndNamed()
    {
        var exception = Assert.Throws<InvalidOperationException>(
            () => "abc".InsertAfter("zzz", "X"));

        Assert.Contains("zzz", exception.Message, StringComparison.Ordinal);
    }

    [Fact]
    public void NotNullOrEmpty_APresentValue_IsReturnedAsIs()
        => Assert.Equal("openid", "openid".NotNullOrEmpty("scope"));

    /// <summary>
    /// The refusal names the value, which is the whole reason this exists instead of a bare null-forgiving
    /// operator: a null travelling on fails somewhere else, and the message there names nothing.
    /// </summary>
    [Theory]
    [InlineData(null)]
    [InlineData("")]
    public void NotNullOrEmpty_AnAbsentValue_ThrowsAndNamesIt(string? value)
    {
        var exception = Assert.Throws<InvalidOperationException>(() => value.NotNullOrEmpty("scope"));

        Assert.Contains("scope", exception.Message, StringComparison.Ordinal);
    }
}
